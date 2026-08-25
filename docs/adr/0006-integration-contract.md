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

## Four concepts that must not merge

Most of the failure modes below are one of these being mistaken for another.

| Concept | Meaning | Produced by |
|---|---|---|
| **Evidence** | what the SDK observed | the device, possibly hostile |
| **Challenge** | which evaluation the evidence belongs to | the backend |
| **Decision** | what the backend concluded | the backend |
| **Freshness** | whether that decision is recent enough *for this operation* | the backend, per action |

And the invariants they exist to protect. Every one of these was learned the expensive way
somewhere between PR #6a and here:

```
INCONCLUSIVE    ≠  TRUSTED
UNAVAILABLE     ≠  TRUSTED
NOT_EVALUATED   ≠  TRUSTED
UNEXPIRED       ≠  FRESH
CLIENT_VERDICT  ≠  SERVER_DECISION
```

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
  "decisionId": "uuid",
  "challenge": "the challenge this decision answers, or null",
  "evaluatedAtMillis": 1735689600000,
  "expiresAtMillis": 1735693200000,
  "actions": ["..."] }
```

**Unexpired is not the same as fresh, and conflating them reopens replay one level up.**
Binding the report to a challenge stops an old *report* being reused; it does nothing about
an old *decision* being reused. A `TRUSTED` issued at app open and valid for an hour says
nothing about the device thirty minutes later, when the user starts moving money.

So the decision carries the challenge it answers, and the rule is:

- **Ordinary use** accepts any unexpired decision.
- **A sensitive action requires a decision whose `challenge` was issued for that action.**
  Not merely unexpired — bound to a challenge minted for this operation.

The backend is the authority on freshness. `expiresAtMillis` is the server's judgement, not
a client-side timer, and the client may shorten it but never extend it.

`INSUFFICIENT_EVIDENCE` is deliberately distinct from `UNAVAILABLE`: the first means the
backend received a report it could not judge (low coverage, inconclusive everywhere), the
second means it never got one. Collapsing them would repeat, at the system level, exactly
the mistake this project spent PRs #6a–#13 removing from the detectors.

**The client cannot declare itself trusted.** `clientAdvisory.verdict` is input to the
backend's decision, never a substitute for it, and the app must branch only on `decision`.

### 6. Security properties, and the uncomfortable one

**Replay.** Without a server challenge, a captured clean report is reusable forever. So the
backend issues a nonce, the app passes it to `evaluate(challenge = nonce)`, and it is echoed
in the report.

Precisely what that buys, since the distinction is easy to lose:

| The challenge establishes | The challenge does **not** establish |
|---|---|
| this report was produced in response to this challenge | that anything in the report is true |
| an old captured report cannot be resubmitted | that a hostile device did not fabricate a fresh one |

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
never blocked by integrity latency**. These only look contradictory while the question is
asked globally. Split by action sensitivity and both hold:

| Situation | Ordinary use | Sensitive action |
|---|---|---|
| Evaluation pending | allow | wait, or evaluate now |
| SDK unavailable | allow | fail closed |
| Network unavailable | allow | fail closed |
| Insufficient evidence | allow | do not approve |
| Server timeout | allow | do not approve |
| Server says `TRUSTED` | allow | allow, if the decision is *fresh* (§5) |
| Server says `COMPROMISED` | restrict | reject |

> **Do not punish ordinary users because security telemetry is slow; do not read missing
> security evidence as proof of trust for security-sensitive operations.**

Which operations count as sensitive is a product decision and belongs in a table the product
owns — money movement, credential change and payee addition are the obvious candidates.

**But sensitivity is a protocol concept, not a product footnote.** The contract carries
`ActionSensitivity` and the two-tier decision rule whether or not the list is agreed,
because the alternative is that someone writes

```ts
if (decision.expiresAtMillis > Date.now()) allowTransaction();
```

and the replay protection becomes a timestamp comparison. The bridge therefore exposes
`mayProceedWithSensitiveAction(decision, issuedChallenge, now)` rather than leaving callers
to inspect the fields: the signature cannot be satisfied without having minted a challenge
for the operation, and `ActionBoundDecision` narrows `challenge` to non-null so a decision
from app open is not assignable. Compiler, not paragraph.

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
   Note that `integrations/react-native/integrity.d.ts` is currently prose that happens to
   parse as TypeScript: no compiler checks it, so it can drift from the Kotlin it describes
   and nothing will notice. **The implementation PR must bring `tsc --noEmit` into CI before
   this contract is described as verified** — the same lesson as the detekt configuration
   that reported zero findings while running a smaller ruleset than the one gating merges.
5. **`integrity-attestation-play` is a stub.** §6 rests on it, so the security value of the
   whole pipeline is currently unimplemented — worth stating before anyone plans around it.

## What CI must enforce once this is built

Design documents are not load-bearing; this project has spent a dozen PRs establishing that.
The implementation is not done until CI rejects each of these:

1. No client-generated trusted verdict reaching a decision path.
2. No treatment of missing evidence as trusted.
3. Challenge bound into the report.
4. Decision bound to the challenge it answers.
5. Sensitive actions requiring an action-bound decision, not merely an unexpired one.
6. A client cannot extend backend freshness — only shorten it.
7. `tsc --noEmit` over the TypeScript contract, before it is described as verified.

Items 1, 2 and 5 are behavioural and want tests that fail when the property is broken —
the mutation gate in `tools/mutate-native.py` is the model: assert that broken code fails,
not merely that correct code passes.

## Resolved

**1. The SDK does not know what "sensitive" means.** The app team owns the list of sensitive
operations, and it lives in the app. The SDK provides *action-bound evaluation* —
`evaluate(challenge)` — and nothing more. It never enumerates operations, never maps an
operation to a policy, and has no notion of which call site is important.

`ActionSensitivity` in the bridge is vocabulary for the app's own table, not a list: two
values, no operations. If the SDK ever grows a `SENSITIVE_OPERATIONS` constant, that is the
architecture leaking and it should be reverted rather than extended.

**2. Ordinary-use decisions are valid for 30 minutes, initially.** Backend-authoritative and
configurable: the number is the server's to change without an app release, and the client
may shorten it but never extend it (§5). Sensitive actions do **not** consume this window —
they require a fresh action-specific challenge and the decision bound to it, so the ordinary
window is irrelevant to them by construction rather than by discipline.

**3. Play Integrity is the authenticated anchor for production decisions.** SDK signals
remain untrusted client observations. The contract keeps the two apart, and the shape below
is what "incorporated without coupling" means concretely.

### Where the Play Integrity token is obtained, and why it matters

The app requests it, not the SDK.

Requesting a token is a network round trip through Play Services. Putting that call inside
the SDK would mean the SDK causes network traffic attributable to the host app, with latency
and failure modes invisible to the app's own Axios layer and its retry policy — which is
what ADR-0003 exists to prevent, whether or not the SDK literally opens the socket itself.
The app already holds the challenge from the backend, so it is also the natural place.

```
backend ──challenge──► app ──┬──► Play Integrity  ──► signed token ──┐
                             │                                       ├──► backend verifies
                             └──► SDK.evaluate(challenge) ──► report ┘
```

The nonce binds both halves: it goes into Play Integrity's `requestHash` and is echoed in
our report. That is a **protocol** coupling, which is wanted. There is no **model** coupling:
the SDK's evidence has no attestation concept, no ATT_* verdict, and no awareness that a
token exists. The backend combines them and owns the scoring policy entirely, so that policy
can change without touching the SDK's evidence model at all.

**Consequence for `integrity-attestation-play`.** That module is currently an empty scaffold
whose stated plan is to produce `ATT_*` detectors from Play Integrity requests on-device.
Under this decision it should not do that: token acquisition belongs to the app. The module
should either be removed or reduced to server-side documentation of how the token is
verified. Flagged rather than changed here — it is a module deletion, and this is a design
PR.

## Still open

1. **Does the backend recompute scoring from signals, or consume `clientAdvisory`?**
   Recomputing is the only version that survives a hostile client.
2. **Nonce lifetime and issuance** — per session, per sensitive action, or per app open?
   Item 2 above settles that a sensitive action needs its own; whether an ordinary-use
   challenge is minted per session or per app open is still open.
