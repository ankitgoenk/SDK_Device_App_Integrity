# 0010. Two nonces, correlated by session at the combiner

Date: 2026-08-31
Status: Accepted. Settles the integration topology left open by
[ADR-0008](0008-attestation-out-of-scope.md), which removed attestation from this project but
did not say what happens to the challenge lifecycle that had been minted alongside it.

## Context

ADR-0008 handed Play Integrity to the app team end to end. Their flow already exists in
production: `/root-enforcement-check` issues a nonce, the app calls
`IntegrityTokenRequest.setNonce(...)`, and `/validate-device-integrity` verifies the token
server-side and returns a last-mile `{rooted: boolean}` summary. The granular verdict reaches
their server; the boolean is what comes back after the decision, so nothing is lost on the way
in.

We also issue a nonce. `InMemoryChallengeStore` mints a challenge bound to a session and a
purpose, redeemable once, inside a backend-authoritative freshness window. `IntegrityGuard`
binds it into the report client-side. That lifecycle was built in PR #20 for the attestation
design and outlived the design it was built for.

So the same logical request carries two nonces from two issuers, with two single-use windows
and two expiry clocks, and something has to line them up. Three shapes were considered:

1. **One nonce, theirs.** Their `/root-enforcement-check` nonce is passed to both Play
   Integrity and our `evaluate(challenge)`; our finding is submitted to their service. One
   issuer, one clock, and `InMemoryChallengeStore` becomes reference material.
2. **Two nonces, correlated by session at the combiner.**
3. **Two nonces, two independent backends.** Ours keeps its own submission path and its own
   view of the request.

Option 3 is the duplication ADR-0008 just deleted, one layer up: a second service with a
second lifecycle answering about the same request, and no place where the two halves meet.
It was rejected on the same reasoning.

Option 1 is the smaller system, and its cost is precise rather than aesthetic. Their nonce is
minted for an attestation round trip. Binding our evidence report to it means our freshness
window, our single-use semantics and our purpose binding all become properties of *their*
issuance — and `ChallengePurpose.satisfies`, which makes a sensitive action require an
action-bound decision, has no counterpart in a nonce minted for Play Integrity. Adopting
their nonce silently drops that distinction, and enforcement property 5 in
`docs/SERVER_VERIFICATION.md` goes with it.

## Decision

**Both nonces stay. Each is issued, redeemed and expired by the service that minted it, and
the combiner correlates them by the host-supplied session identifier.**

1. Our challenge lifecycle **ships**. `InMemoryChallengeStore`, `ChallengePurpose` and the
   backend-authoritative windows are production surface, not a reference implementation.
2. The correlation key is the **session identifier supplied by the host**. It is not a device
   identifier, and one is not to be added to the report to make the join easier — that is hard
   rule 3, and it is also the join-key constraint in the weight-promotion gates. The host
   already holds a session; both services are told about the same one.
3. **Neither nonce validates the other.** A report bound to our challenge says nothing about
   whether their token was fresh, and vice versa. The combiner holds two independent
   assertions about one session and is the only place that knows they are about one session.
4. **Where the two windows disagree, the shorter governs.** This is the existing
   `windowFor` rule — a participant may shorten freshness, never extend it — applied across
   services rather than within one. A stale half makes the correlated pair stale.
5. **A missing half is not a passing half.** If our finding does not arrive, the combiner has
   attestation and no evidence; it does not have evidence of a clean device. Symmetrically, a
   missing token does not make our `NO_EVIDENCE_OF_COMPROMISE` into a pass. This is ADR-0007
   restated at the seam, where it is easiest to lose.

## Consequences

**Purpose binding survives, and it is the reason to accept the extra moving part.** A
sensitive action can still demand a fresh, action-bound decision from us, because we still
mint the thing that carries the purpose. Under option 1 that capability would have had to be
rebuilt inside their nonce format or abandoned, and abandoning it would have quietly voided a
property the test suite currently pins.

**Two clocks is a real cost, and it is paid at the combiner.** Correlation is now a thing that
can be got wrong: mismatched sessions, one half arriving late, a retry that redeems one nonce
and not the other. None of that existed under option 1. The mitigation is that the failure
mode is safe by construction — an uncorrelated pair is two assertions about nothing, and rule
5 says that is never a pass.

**The combiner becomes the only component that sees the whole request, and it is not in this
repository.** Nothing here can test the correlation end to end. `sample-backend` can prove its
own half — that a challenge is single-use, purpose-bound and expires on our clock — and that
is the limit of what this repo may claim. Do not describe the correlated flow as verified.

**Retention is now the open question, and it gates weight promotion rather than this ADR.**
Whether their service retains the granular verdict per session, or only the decision,
determines whether conditional precision analysis is possible at all. Two nonces make the
correlation *possible*; they do not make the history *available*. That is gate 2, and it is
still unanswered.

**Reversing to option 1 stays cheap.** Collapsing to a single issuer later means deleting our
issuance and rebinding `IntegrityGuard`, with the purpose-binding loss made explicit at that
point. Nothing in this decision is load-bearing for the detectors or the scorer.
