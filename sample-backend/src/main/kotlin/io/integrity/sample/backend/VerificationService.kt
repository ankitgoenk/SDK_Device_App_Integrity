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
 * Not implemented here: report signature verification, which needs key distribution, and
 * parsing the canonical wire form. Both are transport concerns; neither changes the above.
 */
class VerificationService(
    private val challenges: ChallengeStore,
    private val scorer: RiskScorer,
    private val decisionPolicy: DecisionPolicy,
    private val clock: ServerClock
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
        val (state, reason) = assess(submission)
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

    private fun assess(submission: ReportSubmission): Pair<DeviceState, DecisionReason> {
        // Full coverage, always. Not the client's number, and not a floor the client can
        // trip: the signals that arrived are scored at face value, and no coverage claim can
        // suppress them. See the class comment.
        val scoring = scorer.score(submission.report.signals, coverage = 1.0f)
        val signalsIncriminate =
            scoring.verdict == Verdict.COMPROMISED || scoring.verdict == Verdict.SUSPICIOUS

        return if (signalsIncriminate) {
            DeviceState.COMPROMISED to DecisionReason.SIGNALS_INDICATE_COMPROMISE
        } else {
            DeviceState.NO_EVIDENCE_OF_COMPROMISE to DecisionReason.NO_SIGNAL_INCRIMINATES
        }
    }
}
