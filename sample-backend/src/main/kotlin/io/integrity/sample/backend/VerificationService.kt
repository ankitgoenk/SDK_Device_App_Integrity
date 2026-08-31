package io.integrity.sample.backend

import io.integrity.core.RiskScorer
import io.integrity.core.Verdict

/**
 * The backend half of the protocol (phase 7): an evidence service, not an access decision.
 *
 * A client-side verdict is an opinion. This grades the evidence behind it. See
 * docs/SERVER_VERIFICATION.md for the full flow.
 *
 * Order of checks, neither of which may be skipped:
 *   1. the challenge is known, unspent, unexpired, and bound to this session;
 *   2. signals are re-scored under the server's policy; `clientAdvisory` is never read.
 *
 * ### Evidence can incriminate. It can never exonerate.
 *
 * A detector that finds nothing emits no signal, so a clean device and a client suppressing
 * everything send byte-identical reports: no signals, coverage 1.0. Nothing the backend can
 * compute distinguishes them, and an earlier draft of this class tried — comparing the report
 * against an expected signal set — which cannot work for exactly that reason.
 *
 * So the report is never a route to trust. Signals are believed when they *incriminate*,
 * because a tampered client has no reason to invent evidence against itself, and ignored when
 * they merely fail to incriminate. That asymmetry used to sit alongside an authenticated
 * anchor that could say `TRUSTED`; ADR-0008 removed the anchor from this service's scope, so
 * what remains is only the incriminating half. [DeviceState.NO_EVIDENCE_OF_COMPROMISE] is the
 * ceiling, and it is an absence rather than a pass.
 *
 * **This service therefore cannot authorise anything on its own, and is not meant to.** The
 * caller holds its own authenticated device signal and combines the two. Wiring this output
 * straight to an allow would reintroduce precisely the hole ADR-0007 closed: send no signals,
 * receive no incrimination, be let in.
 *
 * The client's `coveragePermille` is consulted nowhere at all, and the scorer is deliberately
 * called with full coverage: its low-coverage gate exists to stop a thin *client-side* report
 * reading as clean, and reusing it here would let a client suppress evidence it had already
 * sent by claiming it had not looked hard.
 *
 * ### Signature verification changes none of the above, deliberately
 *
 * A [ReportVerifier] may be supplied, and when it is, a signature that *fails* adds
 * `SRV_REPORT_SIGNATURE_INVALID` to the evidence being scored. A signature that succeeds adds
 * nothing, and is indistinguishable downstream from a report that carried no signature at all
 * — [ReportVerifier.signalsFrom] returns an empty list for both, so there is no branch here
 * that could reward one.
 *
 * The evidence in a badly-signed report is still scored. Letting a broken signature suppress
 * signals would hand a compromised device an escape from `COMPROMISED`: corrupt the signature,
 * lose the accusation. See ADR-0011 §2.
 */
class VerificationService(
    private val challenges: ChallengeStore,
    private val scorer: RiskScorer,
    private val decisionPolicy: DecisionPolicy,
    private val clock: ServerClock,
    /**
     * Null when this deployment has no key enrollment, in which case envelopes are not
     * checked at all.
     *
     * Not checking is a safe default in the only sense that matters here: it can fail to
     * incriminate, and it can never exonerate. The opposite default — verifying against an
     * empty key registry — would raise `SRV_REPORT_SIGNATURE_INVALID` against every honest
     * host that had not enrolled yet.
     */
    private val verifier: ReportVerifier? = null
) {

    fun issueChallenge(sessionId: String, purpose: ChallengePurpose = ChallengePurpose.ORDINARY_USE): Challenge =
        challenges.issue(sessionId, purpose)

    fun verify(
        submission: ReportSubmission,
        requiredPurpose: ChallengePurpose = ChallengePurpose.ORDINARY_USE
    ): Decision {
        val redemption = challenges.redeem(
            submission.report.challenge,
            submission.sessionId,
            requiredPurpose
        )
        if (redemption !is RedemptionResult.Accepted) {
            // No challenge, no finding. Not "no finding yet" — a refusal, with no window.
            return Decision(
                deviceState = DeviceState.INSUFFICIENT_EVIDENCE,
                reason = DecisionReason.CHALLENGE_REJECTED,
                challenge = null,
                purpose = null,
                expiresAtMillis = clock.nowMillis()
            )
        }
        val challenge = redemption.challenge
        val (state, reason) = assess(submission, verifier?.check(submission.envelope))
        return Decision(
            deviceState = state,
            reason = reason,
            challenge = challenge.value,
            purpose = challenge.purpose,
            expiresAtMillis = clock.nowMillis() + windowFor(challenge.purpose, submission)
        )
    }

    /**
     * The window the server grants, which a client may shorten and never extend.
     *
     * `coerceAtMost` rather than a comparison an edit could invert: a request longer than the
     * server's window has no effect at all.
     */
    private fun windowFor(purpose: ChallengePurpose, submission: ReportSubmission): Long {
        val granted = decisionPolicy.windowFor(purpose)
        val requested = submission.requestedMaxAgeMillis ?: return granted
        return granted.coerceAtMost(requested.coerceAtLeast(0L))
    }

    private fun assess(
        submission: ReportSubmission,
        signatureCheck: SignatureCheck?
    ): Pair<DeviceState, DecisionReason> {
        // Evidence from the report and evidence about the report, scored together. The
        // concatenation only ever grows the list: there is no path on which a signature
        // removes a signal the client sent.
        val signatureSignals = signatureCheck
            ?.let { verifier?.signalsFrom(it) }
            .orEmpty()

        // Full coverage, always. Not the client's number, and not a floor the client can
        // trip: the signals that arrived are scored at face value, and no coverage claim can
        // suppress them. See the class comment.
        val scoring = scorer.score(submission.report.signals + signatureSignals, coverage = 1.0f)
        val signalsIncriminate =
            scoring.verdict == Verdict.COMPROMISED || scoring.verdict == Verdict.SUSPICIOUS

        return if (signalsIncriminate) {
            DeviceState.COMPROMISED to DecisionReason.SIGNALS_INDICATE_COMPROMISE
        } else {
            DeviceState.NO_EVIDENCE_OF_COMPROMISE to DecisionReason.NO_SIGNAL_INCRIMINATES
        }
    }
}
