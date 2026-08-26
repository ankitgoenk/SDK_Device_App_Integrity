package io.integrity.sample.backend

import io.integrity.core.RiskScorer
import io.integrity.core.Verdict

/**
 * The backend half of the protocol (phase 7).
 *
 * A client-side verdict is an opinion; the decision that matters is made here. See
 * docs/SERVER_VERIFICATION.md for the full flow.
 *
 * Order of checks, none of which may be skipped:
 *   1. the challenge is known, unspent, unexpired, and bound to this session;
 *   2. signals are re-scored under the server's policy; `clientAdvisory` is never read;
 *   3. the Play Integrity token verifies, and its requestHash matches the challenge;
 *   4. the two views are combined **asymmetrically**, which is the load-bearing idea here.
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
 * they merely fail to incriminate. TRUSTED comes only from the authenticated anchor. This is
 * ADR-0006's "the challenge does not establish that anything in the report is true", turned
 * into control flow.
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
    private val verifier: PlayIntegrityVerifier,
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
            // No challenge, no decision. Not "no decision yet" — a refusal, with no window.
            return Decision(
                action = Action.DENY,
                deviceState = DeviceState.INSUFFICIENT_EVIDENCE,
                reason = DecisionReason.CHALLENGE_REJECTED,
                challenge = null,
                purpose = null,
                expiresAtMillis = clock.nowMillis()
            )
        }
        val challenge = redemption.challenge
        val (state, reason) = assess(submission, challenge)
        return Decision(
            action = decisionPolicy.actionFor(state, challenge.purpose),
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

    private fun assess(submission: ReportSubmission, challenge: Challenge): Pair<DeviceState, DecisionReason> {
        val report = submission.report

        // Full coverage, always. Not the client's number, and not a floor the client can
        // trip: the signals that arrived are scored at face value, and no coverage claim can
        // suppress them. See the class comment.
        val scoring = scorer.score(report.signals, coverage = 1.0f)
        val signalsIncriminate =
            scoring.verdict == Verdict.COMPROMISED || scoring.verdict == Verdict.SUSPICIOUS

        val attestation = submission.playIntegrityToken?.let(verifier::verify)
            ?: AttestationOutcome.Unavailable

        return when {
            // Evidence against interest is believed first, whatever attestation says.
            signalsIncriminate ->
                DeviceState.COMPROMISED to DecisionReason.SIGNALS_INDICATE_COMPROMISE

            // Exhaustive over the sealed type, with no `else`. An earlier version had one,
            // and it was unreachable — which meant mutating it to TRUSTED changed nothing any
            // test could see. Exhaustiveness moves that from "untested branch" to "will not
            // compile when a case is added", which is the stronger guarantee.
            else -> when (attestation) {
                is AttestationOutcome.Invalid ->
                    DeviceState.COMPROMISED to DecisionReason.ATTESTATION_INVALID
                is AttestationOutcome.Unavailable ->
                    DeviceState.UNAVAILABLE to DecisionReason.ATTESTATION_UNAVAILABLE
                is AttestationOutcome.Verified -> stateOf(attestation, challenge)
            }
        }
    }

    /**
     * A token that verified still has to be about *this* app, *this* device and *this*
     * challenge. Every failure here is COMPROMISED rather than UNAVAILABLE: the answer arrived
     * and it was wrong, which is a finding, not an absence.
     */
    private fun stateOf(
        attestation: AttestationOutcome.Verified,
        challenge: Challenge
    ): Pair<DeviceState, DecisionReason> = when {
        !attestation.appRecognised -> DeviceState.COMPROMISED to DecisionReason.APP_NOT_RECOGNISED
        !RequestHash.matches(RequestHash.of(challenge.value), attestation.requestHash) ->
            DeviceState.COMPROMISED to DecisionReason.REQUEST_HASH_MISMATCH
        !attestation.deviceRecognised ->
            DeviceState.COMPROMISED to DecisionReason.DEVICE_NOT_RECOGNISED
        else -> DeviceState.TRUSTED to DecisionReason.OK
    }

    companion object {
        /**
         * Builds a service for production, refusing any verifier that does not talk to Google.
         *
         * The interface boundary is only a comment unless something enforces it, and the way it
         * fails is that a fixture ships. This is the enforcement.
         */
        fun forProduction(
            challenges: ChallengeStore,
            verifier: PlayIntegrityVerifier,
            scorer: RiskScorer,
            decisionPolicy: DecisionPolicy,
            clock: ServerClock
        ): VerificationService {
            require(verifier !is NotForProduction) {
                "refusing to build a production VerificationService around ${verifier::class.simpleName}, " +
                    "which is marked NotForProduction and does not verify anything against Google"
            }
            return VerificationService(challenges, verifier, scorer, decisionPolicy, clock)
        }
    }
}
