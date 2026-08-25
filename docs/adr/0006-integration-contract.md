# ADR-0006: The app/SDK/backend integration contract

**Status:** proposed. No implementation exists.

## Context

The SDK is initialised when the host app opens, evaluates asynchronously, and produces an
`IntegrityReport`. The host is a React Native app with an established Axios layer
(`OneAxios`, interceptors, Zustand, React Query). The backend makes the security decision.

The split, which everything below serves:

```
SDK collects evidence → app transports → backend decides → app enforces
```

ADR-0003 already forbids network IO in the SDK, and this ADR is the reason that rule exists
rather than a preference: the app owns transport, so there is exactly one networking stack,
one place authentication lives, and one place to reason about retries.

## Decision

### 1. Native SDK API

Already close to what is needed. Two changes.

```kotlin
IntegrityGuard.initialize(context, config)          // returns immediately, starts nothing
suspend fun evaluate(depth: Depth, force: Boolean = false, challenge: String? = null)
```

- **Initialise on app open; never evaluate on the critical path.** `initialize` registers
  detectors and returns. Evaluation is launched by the host on its own scope.
- **Repeatable.** `force = false` serves a cached report within its freshness window;
  `force = true` re-runs.
- **Concurrent calls coalesce.** A second `evaluate` while one is running joins the
  in-flight sweep rather than starting a second. Two sweeps would double the cost and
  produce two reports for one device state.
- **`challenge` is new** (§6) and is the only API change this contract requires.

### 2. The report on the wire

The in-process `IntegrityReport` is not the wire format. Two things must change at the
boundary, and both are corrections to how the current model would serialise:

**`verdict` and `riskScore` move under `clientAdvisory`.** The SDK computes them, and they
are useful — the backend can compare its own scoring against the client's, and a divergence
is itself interesting. But a field called `verdict` at the top level of a JSON object is an
invitation to write `if (report.verdict === 'TRUSTED')` in the app, which is precisely the
thing this architecture exists to prevent. The name should make misuse read as wrong.

**Coverage and `INCONCLUSIVE` must survive serialisation.** Hard rule 2 is enforced
in-process today and would be lost at the boundary if the wire format dropped inconclusive
signals as uninteresting. A report with coverage 0.3 and five inconclusive signals must not
arrive at the backend looking like a clean device.

```jsonc
{
  "sdkVersion": "0.1.0-alpha01",
  "reportId": "uuid",              // idempotency key, not a security token
  "generatedAtMillis": 1735689600000,
  "depth": "FULL",
  "challenge": "server-issued-nonce-or-null",
  "coverage": 0.83,                // fraction of detectors that reached a conclusion
  "signals": [
    { "id": "ROOT_DANGEROUS_PROPS", "category": "ROOT",
      "confidence": "POSSIBLE", "evidence": { "tags": "test-keys" } },
    { "id": "APP_SIGNATURE_MISMATCH", "category": "APP_TAMPER",
      "confidence": "INCONCLUSIVE", "evidence": { "reason": "no_pin_configured" } }
  ],
  "clientAdvisory": {              // never authoritative; see §5
    "verdict": "TRUSTED",
    "riskScore": 0,
    "categoryScores": { "ROOT": 0 }
  }
}
```

Evidence values stay bounded and non-PII, per hard rule 3, unchanged by serialisation.

### 3. React Native bridge

Promise-based, matching the app's existing async style. Full interface in
`integrations/react-native/integrity.d.ts`.

```ts
initialize(config): Promise<void>
evaluate(options?): Promise<IntegrityReport>          // resolves when the sweep completes
addListener('integrityReport', cb): Subscription      // for late or background completion
```

Both a promise and an event, because the app may navigate away before a `FULL` sweep
finishes and the report should not be lost. Errors reject with a typed code rather than a
string, so the app can branch on the reason without parsing English.

### 4. App → backend

The app attaches what only the app knows: session, user, device install id, app version,
Play Integrity token. **The SDK contributes none of it** — every one of those is either PII
or authentication state, and putting them in the SDK would breach hard rule 3 and ADR-0003
at once.

```jsonc
{ "integrityReport": { /* §2 */ }, "attestation": { "playIntegrityToken": "..." },
  "context": { "appVersion": "...", "sessionId": "..." } }
```

### 5. Backend → app

```jsonc
{ "decision": "TRUSTED | COMPROMISED | UNAVAILABLE | INSUFFICIENT_EVIDENCE",
  "decisionId": "uuid", "expiresAtMillis": 1735693200000, "actions": ["..."] }
```

`INSUFFICIENT_EVIDENCE` is deliberately distinct from `UNAVAILABLE`: the first means the
backend received a report it could not judge (low coverage, inconclusive everywhere), the
second means it never got one. Collapsing them would repeat, at the system level, exactly
the mistake this project spent PRs #6a–#13 removing from the detectors.

**The client cannot declare itself trusted.** `clientAdvisory.verdict` is input to the
backend's decision, never a substitute for it, and the app must branch only on `decision`.

### 6. Security properties, and the uncomfortable one

**Replay.** Without a server challenge, a captured clean report is reusable forever. So the
backend issues a nonce, the app passes it to `evaluate(challenge = nonce)`, and it is echoed
in the report. That defeats naive replay.

**It does not defeat a compromised client, and nothing in this SDK can.** Our signals are
unsigned claims from a device that may be hostile. A rooted device can send a perfect clean
report, and the echoed nonce will be perfectly correct. This has to be said plainly here,
because a backend team reading a document full of detector names will otherwise reasonably
assume the evidence is trustworthy:

> **The SDK's evidence is advisory. The only authenticated anchor available is Play
> Integrity, whose token is signed by Google and verifiable server-side.**

That gives the honest division:

| | Trust |
|---|---|
| Play Integrity token | verifiable server-side; the anchor |
| SDK signals | unauthenticated claims; useful for texture, telemetry and raising suspicion |
| `clientAdvisory` | a hint about what the client thought; never authority |

The nonce should be bound into the Play Integrity request hash, so the *attested* half is
what carries freshness. Our report riding alongside inherits no authenticity from it, and
must not be described as though it does.

## Sequence, and the state the app tracks

```
app open ──► initialize()            returns immediately, nothing runs
                │
                ├──► (app decides when) evaluate(challenge?)  ── off the critical path
                │            │
                │            ▼
                │      IntegrityReport ──► bridge ──► OneAxios ──► backend
                │                                                     │
                │                                          decision + expiresAt
                │                                                     ▼
                └────────────────────────────────────────────► app enforces
```

The app tracks one value, and every state that is not `TRUSTED` is a state in which the app
has *not* been told the device is fine:

```
NOT_EVALUATED ──► EVALUATING ──► REPORT_READY ──► DECIDED(TRUSTED|COMPROMISED)
      │                │               │                      │
      │                │               └──► UNAVAILABLE ◄──────┘  (transport failed,
      │                └──► UNAVAILABLE                            or decision expired)
      └──────────────────► UNAVAILABLE
```

`NOT_EVALUATED`, `EVALUATING`, `REPORT_READY` and `UNAVAILABLE` are all "not trusted yet".
Only `DECIDED(TRUSTED)`, unexpired, is trust — and it is trust the *server* granted.

## Failure and latency

The governing rule: **absence of a result never means trusted**, and **ordinary users are
never blocked by integrity latency**. Those two pull against each other, and the resolution
is per-action rather than global — see the unresolved decisions.

| Case | Behaviour |
|---|---|
| SDK evaluation fails | report with `INCONCLUSIVE` signals and reduced coverage; never a clean report |
| Evaluation still running | app proceeds; the event delivers the report when it lands |
| Network fails / backend times out | last decision within `expiresAtMillis` applies; otherwise `UNAVAILABLE` |
| Backend returns `UNAVAILABLE` | app treats as "unknown", not "trusted" |
| App backgrounded mid-sweep | sweep is cancellable; a partial sweep is reported with its real coverage |
| Repeated evaluations | coalesced while in flight; cached within the freshness window |
| Stale decision | `expiresAtMillis` governs; expired decisions are not reused |

## Conflicts with the current SDK design

1. **`evaluate` has no `challenge` parameter.** Required for §6; the only API change here.
2. **`verdict`/`riskScore` are top-level today.** They must be fenced as advisory before any
   host sees this shape, or the architecture leaks on first contact.
3. **No serialisation exists.** `IntegrityReport` has no wire form, and writing one is where
   coverage and `INCONCLUSIVE` are most likely to be quietly dropped.
4. **No React Native module exists.** New surface, and the first non-Kotlin consumer.
5. **`integrity-attestation-play` is a stub.** §6 rests on it, so the security value of the
   whole pipeline is currently unimplemented — worth stating before anyone plans around it.

## Unresolved — these need answers before implementation

1. **Fail-open or fail-closed, per action?** "Never block users" and "absence is not trust"
   cannot both hold universally. Recommendation: low-risk actions proceed on `UNAVAILABLE`;
   money movement and credential changes wait or degrade. **This is a product decision, not
   an engineering one**, and it should be written down as a table of actions.
2. **Freshness window** for a cached report, and for a backend decision.
3. **Does the backend recompute scoring from signals, or consume `clientAdvisory`?**
   Recomputing is the only version that survives a hostile client.
4. **Nonce lifetime and issuance** — per session, per sensitive action, or per app open?
5. **Is Play Integrity in scope now?** If not, §6 has no anchor and the backend should treat
   every report as unauthenticated until it is.
