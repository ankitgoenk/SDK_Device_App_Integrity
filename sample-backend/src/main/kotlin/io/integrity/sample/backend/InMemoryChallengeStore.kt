package io.integrity.sample.backend

import java.security.SecureRandom
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Reference [ChallengeStore]: unpredictable values, server-clock expiry, and single use that
 * is atomic rather than merely checked.
 *
 * A real deployment replaces the map with shared storage, and the same property has to hold
 * there: a compare-and-set, not a read followed by a write. The first draft of this class did
 * the obvious `if (value in redeemed) reject; redeemed += value`, which passes every
 * sequential test and loses roughly 3% of contended rounds.
 */
class InMemoryChallengeStore(private val clock: ServerClock) : ChallengeStore {

    private class Entry(val challenge: Challenge) {
        val spent = AtomicBoolean(false)
    }

    private val random = SecureRandom()
    private val entries = ConcurrentHashMap<String, Entry>()

    override fun issue(sessionId: String, purpose: ChallengePurpose): Challenge {
        val now = clock.nowMillis()
        val bytes = ByteArray(VALUE_BYTES).also(random::nextBytes)
        val challenge = Challenge(
            value = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes),
            purpose = purpose,
            sessionId = sessionId,
            issuedAtMillis = now,
            expiresAtMillis = now + DEFAULT_TTL_MILLIS
        )
        entries[challenge.value] = Entry(challenge)
        return challenge
    }

    override fun redeem(
        reportChallenge: String?,
        sessionId: String,
        requiredPurpose: ChallengePurpose
    ): RedemptionResult {
        val entry = reportChallenge?.let { entries[it] }
        return when (val failure = firstFailure(reportChallenge, entry, sessionId, requiredPurpose)) {
            null -> RedemptionResult.Accepted(requireNotNull(entry).challenge)
            else -> RedemptionResult.Rejected(failure)
        }
    }

    /**
     * The ordered checks, as an ordered expression. Order is the security property here, not a
     * stylistic choice, so it is written where it can be read in one go.
     *
     * Expiry is decided against [ServerClock] alone. The report's own `generatedAtMillis` is
     * not a parameter of this function and must never become one: it is attacker-controlled,
     * and reading it would let a client extend the window it exists to be constrained by.
     */
    private fun firstFailure(
        reportChallenge: String?,
        entry: Entry?,
        sessionId: String,
        requiredPurpose: ChallengePurpose
    ): RedemptionFailure? = when {
        reportChallenge == null -> RedemptionFailure.REPORT_NOT_BOUND
        entry == null -> RedemptionFailure.UNKNOWN_CHALLENGE
        clock.nowMillis() >= entry.challenge.expiresAtMillis -> RedemptionFailure.EXPIRED
        entry.challenge.sessionId != sessionId -> RedemptionFailure.SESSION_MISMATCH
        !entry.challenge.purpose.satisfies(requiredPurpose) -> RedemptionFailure.PURPOSE_MISMATCH
        // Consuming the challenge comes last, and only once every check above has passed: a
        // stolen value presented with the wrong session would otherwise burn a victim's
        // challenge, turning a failed forgery into a denial of service.
        !entry.spent.compareAndSet(false, true) -> RedemptionFailure.ALREADY_REDEEMED
        else -> null
    }

    companion object {
        /**
         * How long a challenge may go unanswered. This is not the decision window: ADR-0006
         * gives ordinary-use *decisions* 30 minutes, and a challenge living that long would
         * widen the window for answering it by two orders of magnitude for no benefit.
         */
        const val DEFAULT_TTL_MILLIS: Long = 120_000L
        private const val VALUE_BYTES = 32
    }
}

/**
 * Whether a challenge minted for this purpose may answer a [required] one.
 *
 * A sensitive-action challenge is strictly stronger, so it also satisfies ordinary use. The
 * reverse is the property that matters: an ordinary challenge must never satisfy a sensitive
 * action, or "sensitive actions need their own challenge" becomes a comment.
 */
private fun ChallengePurpose.satisfies(required: ChallengePurpose): Boolean =
    required == ChallengePurpose.ORDINARY_USE || this == ChallengePurpose.SENSITIVE_ACTION
