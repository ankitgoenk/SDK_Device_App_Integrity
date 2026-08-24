package io.integrity.sample.backend

/**
 * Worked example of the backend half of the protocol (phase 7).
 *
 * The whole point of this file existing in phase 0 is to keep the protocol honest while
 * the client is built: a client-side verdict is an opinion, and the decision that matters
 * is made here. See docs/SERVER_VERIFICATION.md for the full flow.
 *
 * Order of checks, none of which may be skipped:
 *   1. nonce is known, unused and unexpired;
 *   2. signature verifies over the canonical report bytes || nonce || package || version;
 *   3. report freshness is within the skew window (clock rollback is itself a signal);
 *   4. the Play Integrity token verifies against Google, and its requestHash matches;
 *   5. signals are re-scored under the *server's* policy — the client score is ignored;
 *   6. client and attestation views are cross-checked; disagreement is the strongest
 *      single signal available, and a missing report is treated as COMPROMISED, not clean.
 */
class VerificationService {

    fun issueNonce(sessionId: String): Nonce =
        TODO("phase 7: 32 random bytes, 120s TTL, single use, bound to $sessionId")

    fun verify(submission: ReportSubmission): Decision =
        TODO("phase 7: run the ordered checks above over nonce=${submission.nonce}, keyId=${submission.keyId}")
}

data class Nonce(val value: String, val expiresAtEpochSeconds: Long)

data class ReportSubmission(
    val canonicalReport: String,
    val signature: String,
    val keyId: String,
    val nonce: String,
    val playIntegrityToken: String?
)

enum class Decision { ALLOW, STEP_UP, REVIEW, DENY }
