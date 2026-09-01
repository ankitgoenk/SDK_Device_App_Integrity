# ADR-0007: Evidence can incriminate, never exonerate

Date: 2026-08-26
**Status:** accepted, implemented in PR #21. Rules out the coverage-reconstruction approach
proposed for that PR, which was never built because it cannot work — see Context.
ADR-0008 supersedes the first Consequence: Play Integrity is no longer an input at all,
so nothing is load-bearing on the trusting side and there is no `TRUSTED` to reach. The
central rule — evidence may only move a decision away from trust — is unchanged and is now
the whole of what this service does.

Mechanics live in `docs/SERVER_VERIFICATION.md`, "Evidence can incriminate. It can never
exonerate." This record exists because the decision is load-bearing and a contributor reading
only the ADRs would otherwise not know it was taken, or that the obvious alternative was tried
and rejected.

## Context

ADR-0006 §5 settled that the backend recomputes the score rather than trusting `clientAdvisory`.
Planning that work, we added what looked like its missing half: the backend would also
reconstruct **coverage** from the signals it expected for a given SDK version and depth, so a
client that simply sent nothing could be caught.

Writing the tests showed it cannot work. `DetectionEngine` derives coverage from how many
detectors *ran*, and a detector that finds nothing emits no signal, so the expected set for a
healthy device is empty. A clean device and a suppressing client send byte-identical reports.

That also sharpens what recomputation buys: it defends against a client lying about its
**verdict**, and does nothing against **omission**, because a noisy-OR over an empty signal
list is zero risk.

## Decision

Signals may only move a decision *away* from trust. `TRUSTED` comes solely from the
authenticated anchor. The client's `coveragePermille` is not an input to scoring, and lives
inside `ClientAdvisory` so it is unreachable from the scoring path by construction rather than
by anyone remembering.

## Consequences

**Play Integrity is load-bearing, and today it is the only load-bearing input — and it is
itself compromisable.** The default policy weights no signal (hard rule 6), so detections
cannot raise a verdict on their own yet. That much is unchanged. What changed is the second
half: on 2026-09-01 the project's rooted Pixel 10a returned `MEETS_BASIC_INTEGRITY`,
`MEETS_DEVICE_INTEGRITY` *and* `MEETS_STRONG_INTEGRITY`, because `tricky_store` presents a
leaked keybox that hardware-backed attestation accepts (TESTING.md §9).

So the stakeholder sentence is now: **"Play Integrity, plus a growing body of evidence that can
veto it — including when Play Integrity itself has been fooled."** Not "our detectors,
corroborated by Google", and no longer "Play Integrity, which is the reliable part".

Two things follow, and both *strengthen* this ADR rather than undermining it. A device that
passes `STRONG` while rooted is precisely the case where evidence-based signals carry unique
value, and the asymmetry means our findings can veto a passing verdict while nothing can move
the other way. And hard rule 6's insistence that reports join to **authoritative fraud
outcomes** — not to attestation verdicts — is now demonstrably load-bearing: had attestation
been permitted as the training label, weight promotion would be fitting against an oracle this
device defeats.

Read the measurement narrowly. One device, one keybox, one moment; Google revokes keyboxes.
It is not "attestation is broken", and this ADR does not license treating a passing verdict as
meaningless. It licenses refusing to treat it as proof.

**A false positive is pure cost.** Since evidence never grants trust, a wrong detection can
only ever harm a legitimate user; there is no offsetting benefit to trade against it. That is
the real reason weights ship at `INFORMATIONAL` until shadow-mode data justifies promotion,
and why every catalogue row carries a false-positive analysis before it ships.

**Changing this needs a new ADR, not a patch.** For the backend to reason about coverage
honestly, the SDK would have to emit an explicit "this detector ran and found nothing" marker
per detector. That changes the evidence model and every detector. Do not add a partial version
of it server-side.
