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

**Implemented.** The scheme below is [ADR-0011](adr/0011-report-signing-without-attestation.md);
it replaces an earlier one described here that ADR-0008 had already made unbuildable. That
earlier text is worth knowing about, because both of its options failed:

- Its *preferred* scheme was ECDSA P-256 with **Keystore key attestation**, so the backend
  could confirm the key lived in a TEE. That is attestation, which ADR-0008 removed from this
  project, and it is an input that would raise confidence in a device, which hard rule 9
  forbids. Remove the attestation and the scheme proves nothing either: the public key then
  arrives self-reported, so anyone can mint a keypair, sign whatever they like, and verify
  perfectly.
- Its *fallback* was HMAC-SHA256 keyed from the build baseline — one secret, identical in
  every install. Extracted once from any APK it forges reports for every user permanently,
  and nothing distinguishes a forgery from the real thing.

What ships instead:

- **ECDSA P-256, non-exportable, in the Android Keystore.** Hardware-backed where the device
  offers it, and nothing checks whether it is — that check is the attestation we do not do.
- **The public key is enrolled over the integrator's own authenticated channel**, the same
  session that carries `sessionId`. Identity comes from their authentication, not from ours.
- **The signature covers the envelope header and the canonical report together**, in the
  compact form `IGS1.<b64url(header)>.<b64url(report)>.<b64url(signature)>`. The nonce is not
  repeated in the header: `challenge` is already inside the report, and a second copy is a
  second thing that can disagree.
- `keyId` is a digest of the public key, derived rather than stored, so it cannot drift from
  the key it names.

**Verification runs over the bytes received, and parsing happens afterwards.** Parsing first
and re-serialising to check the signature would make every difference between
`ReportWireParser` and `ReportWire` a bypass, silently, for as long as the two agreed.

#### A valid signature is worth nothing, and that is the point

The rule that governs the whole feature, and the one a reasonable implementation gets
backwards:

| Case | Effect on the finding |
| --- | --- |
| No signature | none — an unfinished integration is not an attack |
| Valid signature | **none** — byte-identical to the unsigned case, and a test pins it |
| Invalid signature | emits `SRV_REPORT_SIGNATURE_INVALID`, which can only move toward `COMPROMISED` |

**Evidence in a badly-signed report is still scored.** If a broken signature discarded the
report, a compromised device would corrupt its own signature to shed a `COMPROMISED` finding
— verification would become the exoneration channel ADR-0007 closed, triggered by breaking
it. `tools/mutate-backend.py` carries five mutants for this, including that one.

**What it does not buy:** nothing here defeats a rooted device, which asks the Keystore to
sign a fabricated report and gets a perfect signature; and nothing here touches the ADR-0007
hole, where a client suppresses every signal and correctly signs the empty result. Signing
addresses forgery, not silence.

#### Where each half is covered

`KeystoreReportSigner` has **no unit tests and can have none** — `AndroidKeyStore` is a device
provider. `KeystoreReportSignerInstrumentedTest` covers it on-device instead, and verifies
signatures with plain JCE rather than through `ReportVerifier`, so an independent oracle
cannot agree with the signer by sharing its bug. It asserts the property the scheme rests on
directly: the private key's `getEncoded()` returns null.

Every positive there is paired with the tamper that must fail — a spliced payload, a spliced
header, a signature checked under the wrong key. The tampers substitute legitimately encoded
parts rather than editing base64 characters, because an edited character can land on a
non-canonical trailing group that `Base64Url` rejects, which would make the envelope fail to
parse and silently skip the control. Neutering the test's own oracle to a constant `true`
fails exactly those three assertions, which is how they are known to be live.

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
| 8 | A valid signature cannot improve a finding | `ReportVerifierTest` — a signed and an unsigned submission carrying the same signals produce identical findings; two mutants in `tools/mutate-backend.py` |
| 9 | A failed signature cannot suppress evidence | `ReportVerifierTest` — a report with a forged signature still scores `COMPROMISED` on its own signals; one mutant |

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
