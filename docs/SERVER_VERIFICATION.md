# Server-Side Verification

The client can be patched. The backend cannot. Everything that matters is decided here.

## Principles

1. The backend never trusts a client verdict — it re-scores the raw signals itself.
2. Every report is bound to a **server-issued nonce** and is single-use.
3. A **missing, stale, malformed or unsigned** report is a risk signal, not a neutral one.
4. Play Integrity tokens are verified **server-side only**, against Google's keys.
5. Decisions are logged with `reportId` so support can explain an outcome later.

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
  │  Play Integrity token request (nonce-bound)  │
  │                                              │
  │  POST /integrity/report                      │
  │   { canonicalReport, signature, keyId,       │
  │     nonce, playIntegrityToken }              │
  │ ─────────────────────────────────────────▶   │  1. nonce valid, unused, unexpired?
  │                                              │  2. signature valid over canonical bytes?
  │                                              │  3. report freshness within skew window?
  │                                              │  4. verify Play Integrity token w/ Google
  │                                              │  5. re-score signals under server policy
  │                                              │  6. cross-check client vs. attestation
  │  ◀───────────────────────────────────────    │  7. persist + decide
  │      { decision, ttl, requiredStepUp }       │
```

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

## Play Integrity

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

The most valuable server-side signal is **disagreement**:

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
score_server = rescore(signals, serverPolicy)          // never trust client score
score_final  = combine(score_server, attestation, deviceHistory, accountRisk)
```

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
