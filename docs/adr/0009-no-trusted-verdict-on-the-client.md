# 0009. The client vocabulary loses `TRUSTED` too

Date: 2026-08-27
Status: Accepted. Completes [ADR-0006](0006-integration-contract.md) §2, which fixed the wire
format and left the in-process type carrying the same hazard. Client-side counterpart to
[ADR-0008](0008-attestation-out-of-scope.md).

## Context

ADR-0006 §2 saw this coming and named it exactly:

> a field called `verdict` at the top level of a JSON object is an invitation to write
> `if (report.verdict === 'TRUSTED')` in the app, which is precisely the thing this
> architecture exists to prevent.

It then fixed the **wire format** — `verdict` and `riskScore` moved under `clientAdvisory`,
where the backend never reads them — and said in as many words that "the in-process
`IntegrityReport` is not the wire format". Which was true, and was where the fix stopped.

So the in-process type kept the hazard the wire had been rid of. Until this ADR:

```kotlin
if (guard.evaluate().verdict == Verdict.TRUSTED) { allowPayment() }   // compiled
```

`IntegrityReport.verdict` is public, `Verdict.TRUSTED` was a public enum member, and the
combination is a security decision taken on the device from unsigned local evidence by an app
team who did nothing wrong except read the API as written. Nothing in the SDK could have
stopped them, because nothing was wrong with their code — the name promised something the
value could not deliver.

ADR-0008 had just removed `TRUSTED` from the server's `DeviceState` on exactly this reasoning.
Leaving the client's intact meant the SDK could make a claim the backend had been forbidden
from making, which is the wrong way round: the server is the half with an authenticated input.

## Decision

**`Verdict.TRUSTED` becomes `Verdict.NO_EVIDENCE_OF_COMPROMISE`.** Renamed, not deleted — it
is a real scoring band (below `lowRiskThreshold`, 0–14 under `balanced()`), and collapsing it
into `LOW_RISK` would change the meaning of a threshold to fix a naming problem.

The new name is deliberately long and deliberately awkward to read as permission. It matches
the server's `DeviceState.NO_EVIDENCE_OF_COMPROMISE`, so the same concept carries the same
name on both sides, and `UNKNOWN` keeps its distinct meaning — "we could not look" — mirroring
the server's `INSUFFICIENT_EVIDENCE`.

`WIRE_VERSION` goes 1 → 2. The changed field lives under `clientAdvisory` and no decision
reads it, so this is not a structural break; it is still a bump, because the *value domain* of
a serialised field changed. Without one, two reports carrying different vocabularies would
claim the same version, and anything storing reports could not tell which enum a historical
`"verdict"` belonged to.

## Consequences

**This is a breaking API change, taken now because now is when it is free.** The artifact is
`0.1.0-alpha01` with no public release; the same rename after one costs every consumer a
migration. `apiCheck` will fail until the dump is regenerated, which is the mechanism working.

**Naming is the entire defence, so it is pinned by a test.** `RiskScorerTest` asserts the
exact membership of `Verdict`, the client-side twin of the `DeviceState` shape assertion in
`VerificationServiceTest`. Adding a rung that reads as permission now fails a test rather than
waiting to be noticed in an integration.

**It does not make the SDK safe to decide with, and must not be described as if it does.** An
app can still branch on `COMPROMISED` and degrade locally — that is a supported use, and
`docs/RISK_SCORING.md` still suggests responses. What changed is that no rung *reads* like a
grant, so the wrong branch is harder to write by accident. A determined integrator can still
treat the bottom rung as a pass; the defence is a signpost, not a wall, and the wall is that
the server never told them yes.

**The reviewer who raised it was right, and the repository had already argued their case.**
ADR-0006 identified this failure mode, fixed one of its two surfaces, and the other one sat
in the public API through eight ADRs and twenty-two merged pull requests. Worth remembering
the next time a decision record says a hazard is handled.
