#!/usr/bin/env python3
"""Break one guard at a time in InMemoryChallengeStore; every mutant must be killed.

Developer tooling, not a CI gate. The suite's own anti-vacuity tests (AntiVacuityTest, and the
race positive control in InMemoryChallengeStoreTest) run in CI and cover the same ground for
wholesale breakage; this catches the subtler edits — a boundary flipped from >= to >, a TTL
quietly widened — that a hand-written broken store would not represent.

Usage: TEST_CMD='./gradlew :sample-backend:test' tools/mutate-backend.py
"""
import pathlib, shutil, subprocess, sys, tempfile, os

SP = pathlib.Path(__file__).parent
# Derived, never hardcoded. The first version of this line carried the absolute path of the
# machine it was written on, so the CI job died with a FileNotFoundError before running a
# single mutant — the same failure tools/check-signal-catalog.py had, for the same reason.
REPO = pathlib.Path(__file__).resolve().parent.parent
BACKEND = "sample-backend/src/main/kotlin/io/integrity/sample/backend"
STORE = f"{BACKEND}/InMemoryChallengeStore.kt"
SERVICE = f"{BACKEND}/VerificationService.kt"
POLICY = f"{BACKEND}/DecisionPolicy.kt"
TEST_CMD = os.environ.get("TEST_CMD", "./gradlew :sample-backend:test")

# (source file, description, exact text to replace, replacement)
MUTANTS = [
    # --- challenge lifecycle ---
    (STORE, "expiry boundary off by one",
     "clock.nowMillis() >= entry.challenge.expiresAtMillis -> RedemptionFailure.EXPIRED",
     "clock.nowMillis() > entry.challenge.expiresAtMillis -> RedemptionFailure.EXPIRED"),
    (STORE, "expiry check removed",
     "clock.nowMillis() >= entry.challenge.expiresAtMillis -> RedemptionFailure.EXPIRED",
     "false -> RedemptionFailure.EXPIRED"),
    (STORE, "session binding removed",
     "entry.challenge.sessionId != sessionId -> RedemptionFailure.SESSION_MISMATCH",
     "false -> RedemptionFailure.SESSION_MISMATCH"),
    (STORE, "purpose binding removed",
     "!entry.challenge.purpose.satisfies(requiredPurpose) -> RedemptionFailure.PURPOSE_MISMATCH",
     "false -> RedemptionFailure.PURPOSE_MISMATCH"),
    (STORE, "ordinary challenge satisfies a sensitive action",
     "required == ChallengePurpose.ORDINARY_USE || this == ChallengePurpose.SENSITIVE_ACTION",
     "true"),
    (STORE, "single use is check-then-act instead of atomic",
     "!entry.spent.compareAndSet(false, true) -> RedemptionFailure.ALREADY_REDEEMED",
     "entry.spent.get().also { entry.spent.set(true) } -> RedemptionFailure.ALREADY_REDEEMED"),
    (STORE, "single use removed entirely",
     "!entry.spent.compareAndSet(false, true) -> RedemptionFailure.ALREADY_REDEEMED",
     "false -> RedemptionFailure.ALREADY_REDEEMED"),
    (STORE, "unbound report treated as merely unknown",
     "reportChallenge == null -> RedemptionFailure.REPORT_NOT_BOUND",
     "reportChallenge == null -> RedemptionFailure.UNKNOWN_CHALLENGE"),
    (STORE, "challenge values become predictable",
     "value = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes),",
     'value = "challenge-" + entries.size,'),
    (STORE, "ttl widened to the decision window",
     "const val DEFAULT_TTL_MILLIS: Long = 120_000L",
     "const val DEFAULT_TTL_MILLIS: Long = 1_800_000L"),

    # --- decision pipeline ---
    (SERVICE, "incriminating signals ignored",
     "            signalsIncriminate ->", "            false ->"),
    (SERVICE, "unreachable attestation becomes trust",
     "is AttestationOutcome.Unavailable ->\n                    DeviceState.UNAVAILABLE",
     "is AttestationOutcome.Unavailable ->\n                    DeviceState.TRUSTED"),
    (SERVICE, "invalid attestation accepted",
     "is AttestationOutcome.Invalid ->\n                    DeviceState.COMPROMISED",
     "is AttestationOutcome.Invalid ->\n                    DeviceState.TRUSTED"),
    (SERVICE, "requestHash binding removed",
     "!RequestHash.matches(RequestHash.of(challenge.value), attestation.requestHash) ->",
     "false ->"),
    (SERVICE, "unrecognised app accepted",
     "!attestation.appRecognised -> DeviceState.COMPROMISED to DecisionReason.APP_NOT_RECOGNISED",
     "false -> DeviceState.COMPROMISED to DecisionReason.APP_NOT_RECOGNISED"),
    (SERVICE, "unrecognised device accepted",
     "!attestation.deviceRecognised ->", "false ->"),
    (STORE, "single use rewritten as a non-atomic read then write",
     "!entry.spent.compareAndSet(false, true) -> RedemptionFailure.ALREADY_REDEEMED",
     "!entry.spent.get().also { entry.spent.set(true) }.let { !it } -> RedemptionFailure.ALREADY_REDEEMED"),
    (SERVICE, "client can extend the decision window",
     "return granted.coerceAtMost(requested.coerceAtLeast(0L))",
     "return requested.coerceAtLeast(0L)"),
    (SERVICE, "client coverage claim gates the scoring",
     "scorer.score(report.signals, coverage = 1.0f)",
     "scorer.score(report.signals, (report.clientAdvisory?.coveragePermille ?: 0) / 1000f)"),
    (SERVICE, "production wiring accepts a fixture verifier",
     "require(verifier !is NotForProduction) {",
     "require(true) {"),
    (SERVICE, "a rejected challenge still yields a decision window",
     "                expiresAtMillis = clock.nowMillis()\n            )",
     "                expiresAtMillis = clock.nowMillis() + 1_800_000L\n            )"),

    # --- decision policy ---
    (POLICY, "an unmapped device state allows",
     "return table[state] ?: Action.DENY", "return table[state] ?: Action.ALLOW"),
    (POLICY, "sensitive actions reuse the ordinary window",
     "if (purpose == ChallengePurpose.SENSITIVE_ACTION) sensitiveWindowMillis else ordinaryWindowMillis",
     "ordinaryWindowMillis"),
    (POLICY, "sensitive policy weakened to allow an unavailable device",
     "DeviceState.UNAVAILABLE to Action.DENY,",
     "DeviceState.UNAVAILABLE to Action.ALLOW,"),
]

# Baseline first, on unmutated source. Without this the gate is satisfiable by a broken test
# command: if TEST_CMD fails for any reason — a compile error, a missing SDK, a typo in the
# command itself — then every mutant "dies" and the run reports a perfect score having
# verified nothing. That happened on the first attempt at this file, so it is checked rather
# than assumed.
print("baseline: running the suite on unmutated source")
baseline = subprocess.run(TEST_CMD, shell=True, cwd=REPO, capture_output=True, text=True)
if baseline.returncode != 0:
    print("FAIL: the suite does not pass before any mutation, so 'every mutant killed' would "
          "mean nothing. Fix the build or TEST_CMD first.", file=sys.stderr)
    print((baseline.stdout + baseline.stderr)[-2000:], file=sys.stderr)
    sys.exit(2)
print("baseline: green\n")

killed, survived = 0, []
for path, name, old, new in MUTANTS:
    target = REPO / path
    original = target.read_text()
    if original.count(old) != 1:
        survived.append(f"{name} [pattern not unique in {path}]")
        print(f"  SKIP (pattern not unique): {name}")
        continue
    target.write_text(original.replace(old, new))
    try:
        r = subprocess.run(TEST_CMD, shell=True, cwd=REPO, capture_output=True, text=True)
        if r.returncode != 0:
            killed += 1
            print(f"  killed:   {name}")
        else:
            survived.append(name)
            print(f"  SURVIVED: {name}")
    finally:
        target.write_text(original)

print(f"\nmutation score: {killed}/{len(MUTANTS)}")
if survived:
    print("survivors (the suite does not detect these):")
    for item in survived:
        print("  -", item)
    sys.exit(1)
