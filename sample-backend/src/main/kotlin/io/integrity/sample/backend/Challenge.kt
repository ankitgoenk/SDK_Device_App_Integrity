package io.integrity.sample.backend

/**
 * Server time, injected so that expiry is testable without sleeping.
 *
 * The important property is not that this is injectable but that it is the *only* clock in
 * the redemption path. A report carries `generatedAtMillis`, which an attacker controls
 * completely; nothing here reads it. See ADR-0006 §6 — a client may shorten backend
 * freshness but must never be able to extend it.
 */
fun interface ServerClock {
    fun nowMillis(): Long
}

/**
 * Why a challenge was minted.
 *
 * This is not a list of sensitive operations and must never become one: the app owns that
 * table (ADR-0006, Resolved 1). It records only whether the backend minted this challenge
 * for ordinary use or for one specific action, which is what lets a sensitive action refuse
 * a decision that merely happens to be unexpired.
 */
enum class ChallengePurpose { ORDINARY_USE, SENSITIVE_ACTION }

/**
 * A server-issued challenge. Every field is the server's: nothing here originates with,
 * or can be influenced by, the client.
 */
data class Challenge(
    val value: String,
    val purpose: ChallengePurpose,
    val sessionId: String,
    val issuedAtMillis: Long,
    val expiresAtMillis: Long
)

/**
 * Why a redemption was refused.
 *
 * These are deliberately distinct rather than a single boolean: the backend wants to tell
 * "this client is behaving oddly" apart from "this client is slow", and collapsing them
 * loses the distinction at exactly the point it becomes interesting.
 */
enum class RedemptionFailure {
    UNKNOWN_CHALLENGE,
    EXPIRED,
    ALREADY_REDEEMED,
    SESSION_MISMATCH,
    PURPOSE_MISMATCH,
    REPORT_NOT_BOUND
}

sealed interface RedemptionResult {
    data class Accepted(val challenge: Challenge) : RedemptionResult

    data class Rejected(val reason: RedemptionFailure) : RedemptionResult
}

/**
 * Issues challenges and redeems them exactly once.
 *
 * This is step 1 of the ordered checks in [VerificationService], and it is separated from
 * scoring on purpose: it decides only *which evaluation this evidence belongs to*, never
 * whether the evidence is good. Those are two of the four concepts ADR-0006 insists must
 * not merge.
 */
interface ChallengeStore {

    fun issue(sessionId: String, purpose: ChallengePurpose): Challenge

    /**
     * Redeems the challenge a report claims to answer.
     *
     * [reportChallenge] is the `challenge` field echoed by the report — nullable because an
     * unbound report is a real submission the backend must reject rather than a programming
     * error. Note what is absent: the report's own timestamp. Expiry is decided against
     * [ServerClock] alone.
     */
    fun redeem(reportChallenge: String?, sessionId: String, requiredPurpose: ChallengePurpose): RedemptionResult
}
