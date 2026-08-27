# Server-Side Verification

The client can be patched. The backend cannot. Everything that matters is decided here.

## Principles

1. The backend never trusts a client verdict — it re-scores the raw signals itself.
2. Every report is bound to a **server-issued nonce** and is single-use.
3. A **missing, stale, malformed or unsigned** report is a risk signal, not a neutral one.
4. This service performs **no device attestation** and never concludes a device is
   trustworthy — ADR-0008. It grades evidence; the integrator decides access.
5. Findings are logged with `reportId` so support can explain an outcome later.

## Protocol

```
Client                                        Backend
  │  POST /integrity/nonce                       │
  │ ─────────────────────────────────────────▶   │  generate 32-byte nonce,
  │                                              │  store {nonce, sessionId, exp=120s}
  │  ◀───────────────────────────────────────    │
  │      { nonce, expiresAt }                    │
  │                                              │
  │  evaluate(FULL) → report                     │
  │                                              │
  │  POST /integrity/report                      │
  │   { canonicalReport, signature, keyId,       │
  │     nonce }                                  │
  │ ─────────────────────────────────────────▶   │  1. nonce valid, unused, unexpired?
  │                                              │  2. signature valid over canonical bytes?
  │                                              │  3. report freshness within skew window?
  │                                              │  4. re-score signals under server policy
  │  ◀───────────────────────────────────────    │  5. persist + return a finding
  │      { deviceState, reason, ttl }            │
```

Attestation is absent from this diagram on purpose (ADR-0008). The integrator runs their own
Play Integrity flow alongside, on their own nonce, and combines its result with the finding
above. Neither leg is this service's to perform, and the combination happens on their side.

### Canonical serialisation

Signing needs byte-stable input. The report serialises to canonical JSON: keys sorted
lexicographically, no insignificant whitespace, integers only (no floats — `coverage` is
serialised as basis points), UTF-8, and a leading `"v"` schema version. The canonicaliser is
covered by round-trip tests; changing it is a schema-version bump.

### Signing

- **Preferred:** ECDSA P-256 with a key generated in the **Android Keystore**, hardware-backed
  where available, with **key attestation** so the backend can verify the key really lives in
  a TEE/StrongBox. This makes signature forgery expensive even on a rooted device.
- **Fallback (no Keystore attestation):** HMAC-SHA256 with a key derived in native code from
  the build baseline. Weaker — it is extractable by a determined attacker — but it stops
  replayed and hand-crafted reports.
- The signature covers: canonical report bytes ‖ nonce ‖ package name ‖ sdk version.
- `keyId` lets the backend rotate and distinguish attestation-backed from fallback keys, and
  score them differently.

### Freshness and replay

- Nonce TTL 120 s, single use, bound to the session/user.
- Reject `generatedAtMillis` more than 120 s from server time (both directions — clock
  rollback is itself a signal).
- Rate-limit report submission per device/session; a burst of reports with different verdicts
  is evidence of tampering experiments.

**Implemented** in `sample-backend` as `ChallengeStore` / `InMemoryChallengeStore`. Three
things about it are not obvious from the bullets above and are worth stating, because each was
either a bug in the first draft or a property a reasonable implementation would miss:

- *Single use has to be atomic, not checked.* `if (spent) reject; spent = true` satisfies every
  sequential test and loses roughly 3% of contended rounds. The store uses a compare-and-set,
  and a replacement backed by shared storage must do the same rather than a read-then-write.
- *Expiry is decided against the server clock alone.* The report's `generatedAtMillis` is not a
  parameter of redemption. It is checked separately as a skew signal (bullet 2 above), but it
  can never affect whether a challenge is still live — otherwise the client extends the window
  that exists to constrain it.
- *Validation precedes consumption.* A challenge presented with the wrong session or purpose is
  rejected without being spent. Consuming it first would let anyone holding a stolen challenge
  value burn a victim's challenge, converting a failed forgery into a denial of service.

A challenge TTL is not a decision window: 120 s to answer a challenge, 30 minutes for the
decision that results (ADR-0006). A test asserts the former stays below the latter, because the
tempting simplification is to unify them.

## Evidence can incriminate. It can never exonerate.

The single most important property of this pipeline, and the one that is easy to get wrong in
a way that looks right.

A detector that finds nothing emits no signal, and `coverage` is computed on-device from how
many detectors ran — not from the signal list. So a clean device and a client suppressing
everything send **byte-identical** reports: no signals, coverage 1.0. There is nothing the
backend can compute that separates them.

An earlier draft of the pipeline tried, by comparing the report against the set of signals the
server expected for that SDK version and depth. It cannot work, for exactly the reason above:
the expected set for a healthy device is empty. Recomputing the score server-side defends
against a client that *lies about its verdict*. It does nothing against a client that simply
**omits**, because a noisy-OR over an empty signal list is zero risk, and an honest
recomputation of nothing says clean.

So the report is never a route to trust:

- Signals are believed when they **incriminate**. A tampered client has no reason to invent
  evidence against itself, so an incriminating signal is credible however it arrived.
- Signals that merely fail to incriminate establish nothing at all.
- There is no `TRUSTED`. This service holds no authenticated anchor (ADR-0008), so the
  strongest finding it can reach is `NO_EVIDENCE_OF_COMPROMISE` — an absence, named to resist
  being skim-read as a pass.

Three consequences worth stating because they read as bugs otherwise:

- **A spotless report earns `NO_EVIDENCE_OF_COMPROMISE`, and so does a client that suppressed
  everything.** They are the same bytes. That is the whole reason the ceiling is where it is.
- **There is no `Action` in the response.** An `ALLOW` this service could emit would be an
  exoneration by another name. The integrator combines this finding with their own attestation
  result and decides; that decision does not happen here.
- **Under the default policy every device comes back `NO_EVIDENCE_OF_COMPROMISE`,** including
  a rooted one, because hard rule 6 ships every signal at `INFORMATIONAL` and `score()` filters
  to promoted signals. A deployment must set its own weights or this pipeline says nothing.

The client's `coveragePermille` is consulted nowhere, and the scorer is deliberately called
with full coverage. Its low-coverage gate exists to stop a thin report reading as clean *on
the device*; reusing it server-side would let a client discard incriminating findings it had
already sent by also claiming it had not looked hard. There is a test for that specific
downgrade.

If we ever want the backend to reason about coverage properly, the SDK has to emit an explicit
"this detector ran and found nothing" marker per detector. That is an SDK change and deserves
its own ADR; it is not a backend problem to solve.

## Enforcement status of the ADR-0006 checklist

ADR-0006 listed what CI must reject before the contract counts as implemented. That record is
not edited after acceptance, so the running score lives here. Update this table in the same PR
as the gate.

| # | Property | Enforced by |
| --- | --- | --- |
| 1 | No client-generated trusted verdict reaching a decision path | `VerificationServiceTest` — five contradictory advisories produce byte-identical findings |
| 2 | No treatment of missing evidence as trusted | `DecisionContract` refusals, run against a permissive pipeline that must fail all of them. Structurally reinforced: `DeviceState` has no trusted member, and a test pins the enum's shape |
| 3 | Challenge bound into the report | `IntegrityGuard` (client, PR #18) and `ChallengeContract` (server) |
| 4 | Finding bound to the challenge it answers | `Decision.challenge` / `.purpose`, asserted in `VerificationServiceTest` |
| 5 | Sensitive actions need an action-bound decision | `ChallengePurpose.satisfies`, plus a mutant that must die |
| 6 | A client cannot extend backend freshness, only shorten it | `windowFor` uses `coerceAtMost`; extend, shorten and negative cases all tested |
| 7 | `tsc --noEmit` over the TypeScript contract | **Not enforced.** The bridge is unbuilt; do not describe it as verified |

Items 1–6 are additionally covered by `tools/mutate-backend.py`, which breaks each guard in
turn and requires every mutant to be caught. That job runs on every commit and refuses to
start unless the suite is green first — otherwise a broken test command kills every mutant and
reports a perfect score.

## Play Integrity — guidance for the integrator, not a description of this service

Everything in this section is **outside this project's scope** (ADR-0008). It is kept because
the integrator running attestation still has to get it right, and this is where the knowledge
was already written down. Nothing here is implemented in `sample-backend`, and no test in this
repository establishes any of it.

Note the API split, because it changes what is possible: the flow below assumes **Standard**
requests with a `requestHash`. A deployment using the **Classic** API binds freshness through
`IntegrityTokenRequest.setNonce(...)` instead, and the two are not interchangeable — a
`requestHash` derived from a challenge will never match a Classic token.

- **Standard requests** for routine checks: cheap, low latency, uses a warm token provider.
  Request `prepareIntegrityToken` at app start; call `request(requestHash = sha256(nonce ‖ payloadDigest))`.
- **Classic requests** for high-value actions only: higher latency and quota, but a full
  fresh evaluation.
- Decrypt/verify **on the server** via the Play Integrity API (Google-managed keys strongly
  preferred over local decryption).
- Map verdicts to signals:

| Play Integrity field | Signal |
| --- | --- |
| `deviceRecognitionVerdict` missing `MEETS_DEVICE_INTEGRITY` | `ATT_DEVICE_INTEGRITY_FAIL` |
| missing `MEETS_BASIC_INTEGRITY` | `ATT_BASIC_INTEGRITY_FAIL` |
| only `MEETS_VIRTUAL_INTEGRITY` | `ATT_VIRTUAL_ONLY` |
| `appIntegrity.appRecognitionVerdict != PLAY_RECOGNIZED` | `ATT_APP_NOT_RECOGNISED` |
| `environmentDetails.appAccessRiskVerdict` non-empty | `ATT_APP_ACCESS_RISK` |
| `environmentDetails.playProtectVerdict` off/no-data | `ENV_PLAY_PROTECT_OFF` |
| token absent/invalid | `ATT_UNEVALUATED` |

Also verify `requestDetails.requestPackageName` matches your package and `requestHash`
matches the nonce binding — otherwise a token from another app or session can be replayed.

**Non-GMS markets:** Play Integrity is unavailable on devices without Play Services (parts of
China, Huawei, some sideload channels). Plan for a second path: vendor attestation
(Huawei SafetyDetect), Android **Key Attestation** verified against Google's hardware
attestation root, or an explicitly higher-friction policy for those devices.

## Cross-checking client vs. attestation

Also integrator-side, and the reason our finding is worth combining with theirs at all: this
comparison needs both halves, and only the integrator holds both. The most valuable signal is
**disagreement**:

| Client says | Attestation says | Interpretation |
| --- | --- | --- |
| clean | device integrity fails | Client checks defeated — treat as `COMPROMISED` |
| root detected | device integrity passes | Unusual; possible client bug or a spoofed positive — investigate |
| clean, low coverage | not evaluated | `UNKNOWN` — require step-up for anything sensitive |
| no report at all | — | SDK stripped or blocked — treat as `COMPROMISED` for high-value actions |

Persist the pair; a shift in this matrix across your user base is the earliest warning that a
public bypass for your app has been published.

## Decision service

```
finding      = rescore(signals, serverPolicy)          // this service; never trusts the client
decision     = combine(finding, attestation, deviceHistory, accountRisk)   // the integrator
```

The split is the point. `finding` is all this repository produces, and it can only ever
accuse. `decision` is where an allow can come from, and it needs an authenticated input that
this service does not have.

Inputs worth combining server-side that the client cannot see:
- device/account history and velocity (many accounts per device signature, many devices per account),
- fleet correlation (identical `evidence` fingerprints across thousands of installs — a device farm),
- geography/IP/ASN mismatch with device locale,
- prior enforcement outcomes.

## Telemetry schema (suggested)

```json
{
  "v": 1,
  "reportId": "uuid",
  "receivedAt": 1710000000,
  "package": "com.example.app",
  "sdkVersion": "1.0.0",
  "depth": "FULL",
  "coverageBp": 9400,
  "clientScore": 62,
  "serverScore": 88,
  "verdict": "COMPROMISED",
  "signals": [
    {"id": "HOOK_FRIDA_MAPS", "confidence": "CONFIRMED", "evidence": {"module": "agent"}}
  ],
  "attestation": {"deviceIntegrity": ["MEETS_BASIC_INTEGRITY"], "appRecognition": "PLAY_RECOGNIZED"},
  "keyId": "ak-hw-01",
  "signatureValid": true
}
```

Retention and PII rules are in [PRIVACY_AND_COMPLIANCE.md](PRIVACY_AND_COMPLIANCE.md). Note
that hashed third-party package identifiers are still device-linkable data — store them under
the same retention policy as other risk telemetry.

## Operational alarms

- Sudden drop in `COMPROMISED` rate → a bypass is circulating (detection went blind).
- Sudden spike → a bad detector shipped or an OEM update changed the environment.
- Rise in `META_NATIVE_UNAVAILABLE` → someone is stripping the `.so`.
- Rise in "no report submitted" for sessions that reach authenticated endpoints → the SDK
  call is being removed.
