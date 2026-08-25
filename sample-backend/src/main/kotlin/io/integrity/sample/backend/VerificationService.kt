package io.integrity.sample.backend

/**
 * Worked example of the backend half of the protocol (phase 7).
 *
 * The whole point of this file existing early is to keep the protocol honest while the client
 * is built: a client-side verdict is an opinion, and the decision that matters is made here.
 * See docs/SERVER_VERIFICATION.md for the full flow.
 *
 * Order of checks, none of which may be skipped:
 *   1. the challenge is known, unspent, unexpired, and bound to this session — **implemented**,
 *      see [ChallengeStore];
 *   2. signature verifies over the canonical report bytes || challenge || package || version;
 *   3. report freshness is within the skew window (clock rollback is itself a signal);
 *   4. the Play Integrity token verifies against Google, and its requestHash matches;
 *   5. signals are re-scored under the *server's* policy — the client score is ignored;
 *   6. client and attestation views are cross-checked; disagreement is the strongest
 *      single signal available, and a missing report is treated as COMPROMISED, not clean.
 *
 * Steps 2–6 are the next PR. They are listed here rather than in a tracker because the order
 * is the security property: step 5 reached without step 1 is a scoring function, not a
 * verification.
 */
class VerificationService(private val challenges: ChallengeStore) {

    /**
     * Mints the challenge for an evaluation.
     *
     * [purpose] is the caller's declaration of what this challenge is for, not the SDK's: the
     * app owns the list of sensitive operations (ADR-0006, Resolved 1). A backend route
     * guarding a payment asks for [ChallengePurpose.SENSITIVE_ACTION]; session start asks for
     * [ChallengePurpose.ORDINARY_USE].
     */
    fun issueChallenge(sessionId: String, purpose: ChallengePurpose = ChallengePurpose.ORDINARY_USE): Challenge =
        challenges.issue(sessionId, purpose)

    fun verify(submission: ReportSubmission): Decision = TODO(
        "steps 2-6 for challenge=${submission.challenge}, keyId=${submission.keyId}: " +
            "signature, freshness, Play Integrity, server-side scoring"
    )
}

data class ReportSubmission(
    val canonicalReport: String,
    val signature: String,
    val keyId: String,
    val challenge: String?,
    val playIntegrityToken: String?
)

/**
 * What the app may do, as distinct from what the device is.
 *
 * The device-state vocabulary (TRUSTED / COMPROMISED / UNAVAILABLE / INSUFFICIENT_EVIDENCE)
 * arrives with the scoring pipeline in the next PR. Keeping the two apart is deliberate:
 * collapsing "what we observed" into "what you may do" is how a missing signal quietly
 * becomes permission.
 */
enum class Decision { ALLOW, STEP_UP, REVIEW, DENY }
