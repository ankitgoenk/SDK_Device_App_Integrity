# 0008. Attestation leaves our scope; the backend becomes an evidence service

Date: 2026-08-27
Status: Accepted. Supersedes the anchor half of [ADR-0006](0006-integration-contract.md) §"Trust
boundary" and Resolved 3, and the first Consequence of [ADR-0007](0007-asymmetric-trust.md).

## Context

ADR-0006 put Play Integrity *token acquisition* in the app, for ADR-0003 reasons: a token
request is a network round trip, and the SDK originates no network traffic. Verification
stayed with us — `sample-backend` held a `PlayIntegrityVerifier`, checked the `requestHash`
against the challenge it had minted, and turned a verified token into `DeviceState.TRUSTED`.

The app team already runs that whole flow in production: `/root-enforcement-check` issues a
nonce, the app calls `IntegrityTokenRequest.setNonce(...)`, and `/validate-device-integrity`
verifies the token server-side. Standing up a second verification path, with a second set of
Google credentials, to answer a question their service already answers, is duplicated cost
and a second thing to keep correct. So attestation is now theirs end to end, and this project
does not perform it.

That has a consequence which has to be stated rather than discovered:

**`VerificationService.stateOf` was the only producer of `TRUSTED` in the pipeline, and it
was reachable only through a verified token.** Left alone, removing attestation would have
sent every submission to `UNAVAILABLE` — `STEP_UP` for ordinary use, `DENY` for sensitive
actions — for every user on every request, including on a perfectly healthy device. Not a
degraded service; a service that refuses everyone while appearing to function.

ADR-0007 established that evidence can incriminate and never exonerate, and named Play
Integrity as the only load-bearing input. Take the anchor out and only the incriminating half
is left. That is a coherent thing to be — but it is a different thing from what ADR-0006
described, and the vocabulary has to say so.

## Decision

**This project performs no device attestation, and its backend never concludes that a device
is trustworthy.**

1. `PlayIntegrityVerifier`, `AttestationOutcome`, `RequestHash` and the `NotForProduction`
   marker are deleted. `ReportSubmission` no longer carries a token.
2. `DeviceState` becomes `COMPROMISED` / `NO_EVIDENCE_OF_COMPROMISE` / `INSUFFICIENT_EVIDENCE`.
   There is no `TRUSTED` and no route to one. `NO_EVIDENCE_OF_COMPROMISE` is an absence, named
   so it cannot be skim-read as a pass.
3. **The `Action` vocabulary is removed.** With no anchor there is no state this service could
   honestly map to `ALLOW`: a client that suppresses every signal earns exactly the same
   finding as a clean device, so an `ALLOW` here would be an exoneration by another name — the
   hole ADR-0007 closed, reopened one layer up. `DecisionPolicy` keeps the freshness windows,
   which remain backend-authoritative and configurable, and loses the state-to-action tables.
4. The access decision belongs to the integrator, who holds both halves: our evidence finding
   and their own attestation result. That combination does not happen in this repository.
5. `SignalId.ATT_APP_NOT_RECOGNISED` stays, and stays in the scorer's `DECISIVE_SIGNALS`. We
   never emit it, but it is the vocabulary under which an integrator feeds their own
   attestation verdict into `RiskScorer` — the one attestation hook that still makes sense.

## Consequences

**This service cannot authorise anything, and that is now structural rather than advisory.**
The previous design could be misused by wiring `Action` straight to an access check. There is
no longer an `Action` to wire.

**The honest description changes.** ADR-0007 said to describe the system as "Play Integrity,
plus a growing body of evidence that can veto it". That is no longer ours to say. It is now
"a body of evidence that can veto a decision made elsewhere" — and since hard rule 6 still
ships every signal at `INFORMATIONAL`, a default-policy deployment vetoes nothing at all. A
backend that takes `Policy.balanced()` and asks this service about a rooted device is told
there is no evidence of compromise. `VerificationServiceTest` pins that, deliberately.

**A false positive is still pure cost, and now it is the only thing we produce.** Every
finding this service can make is an accusation. There is no offsetting benefit anywhere in
the output to trade against a wrong one.

**The anti-vacuity surface moved and had to be rebuilt, not just trimmed.** `DecisionContract`
refused on `action == ALLOW || deviceState == TRUSTED`; both names are gone, so the compiler
forced a rewrite, and a wrong rewrite would have left nine assertions green and meaningless
with nothing in the diff to show it. The predicate now refuses on `NO_EVIDENCE_OF_COMPROMISE`,
and `AntiVacuityTest` runs every check against a harness returning exactly that. Both
plausible wrong rewrites were tried against that guard and both fail it.

Five of the nine refusals concerned attestation and went with it; four pipeline-level
binding refusals replaced them, so the count did not fall. The mutation suite did fall, 24 to
19, because six attestation mutants had no code left to break. No surviving guard lost its
mutant.

**Reversing this is additive, which is why it was the safe direction.** If an authenticated
anchor is ever wired in — their service calling ours with an already-verified result — it
arrives as a new input and a new state. Nothing here has to be undone first.
