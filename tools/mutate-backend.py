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
REPO = pathlib.Path("/home/user/SDK_Device_App_Integrity")
SRC = "sample-backend/src/main/kotlin/io/integrity/sample/backend/InMemoryChallengeStore.kt"
TEST_CMD = os.environ.get("TEST_CMD", "./gradlew :sample-backend:test")

MUTANTS = [
    ("expiry boundary off by one",
     "clock.nowMillis() >= entry.challenge.expiresAtMillis -> RedemptionFailure.EXPIRED",
     "clock.nowMillis() > entry.challenge.expiresAtMillis -> RedemptionFailure.EXPIRED"),
    ("expiry check removed",
     "clock.nowMillis() >= entry.challenge.expiresAtMillis -> RedemptionFailure.EXPIRED",
     "false -> RedemptionFailure.EXPIRED"),
    ("session binding removed",
     "entry.challenge.sessionId != sessionId -> RedemptionFailure.SESSION_MISMATCH",
     "false -> RedemptionFailure.SESSION_MISMATCH"),
    ("purpose binding removed",
     "!entry.challenge.purpose.satisfies(requiredPurpose) -> RedemptionFailure.PURPOSE_MISMATCH",
     "false -> RedemptionFailure.PURPOSE_MISMATCH"),
    ("ordinary challenge satisfies a sensitive action",
     "required == ChallengePurpose.ORDINARY_USE || this == ChallengePurpose.SENSITIVE_ACTION",
     "true"),
    ("single use is check-then-act instead of atomic",
     "!entry.spent.compareAndSet(false, true) -> RedemptionFailure.ALREADY_REDEEMED",
     "entry.spent.get().also { entry.spent.set(true) } -> RedemptionFailure.ALREADY_REDEEMED"),
    ("single use removed entirely",
     "!entry.spent.compareAndSet(false, true) -> RedemptionFailure.ALREADY_REDEEMED",
     "false -> RedemptionFailure.ALREADY_REDEEMED"),
    ("unbound report treated as merely unknown",
     "reportChallenge == null -> RedemptionFailure.REPORT_NOT_BOUND",
     "reportChallenge == null -> RedemptionFailure.UNKNOWN_CHALLENGE"),
    ("challenge values become predictable",
     "value = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes),",
     'value = "challenge-" + entries.size,'),
    ("ttl widened to the decision window",
     "const val DEFAULT_TTL_MILLIS: Long = 120_000L",
     "const val DEFAULT_TTL_MILLIS: Long = 1_800_000L"),
]

original = (REPO / SRC).read_text()
killed, survived = 0, []
for name, old, new in MUTANTS:
    if original.count(old) != 1:
        print(f"  SKIP (pattern not unique): {name}"); survived.append(name + " [pattern]"); continue
    (REPO / SRC).write_text(original.replace(old, new))
    try:
        r = subprocess.run(TEST_CMD, shell=True, cwd=REPO, capture_output=True, text=True)
        if r.returncode != 0:
            killed += 1; print(f"  killed:   {name}")
        else:
            survived.append(name); print(f"  SURVIVED: {name}")
    finally:
        (REPO / SRC).write_text(original)

print(f"\nmutation score: {killed}/{len(MUTANTS)}")
if survived:
    print("survivors (the suite does not detect these):")
    for s in survived: print("  -", s)
    sys.exit(1)
