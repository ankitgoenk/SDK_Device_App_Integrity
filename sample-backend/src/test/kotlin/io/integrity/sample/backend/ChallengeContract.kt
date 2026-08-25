package io.integrity.sample.backend

/**
 * The challenge-lifecycle properties, expressed so they can be run against *any*
 * [ChallengeStore].
 *
 * They are a list of named checks rather than a pile of @Test methods because they have two
 * callers. [InMemoryChallengeStoreTest] asserts the real store satisfies all of them; the
 * anti-vacuity suite asserts that a store which accepts everything fails every rejection,
 * and a store which refuses everything fails every acceptance. A test suite that a permissive
 * implementation can satisfy is not testing anything, and the only way to know is to try one.
 */
internal class MutableClock(private var millis: Long = START_MILLIS) : ServerClock {
    override fun nowMillis(): Long = millis

    fun advanceBy(delta: Long) {
        millis += delta
    }

    companion object {
        /** Arbitrary but non-zero: a store that returns 0 from a broken clock read stands out. */
        const val START_MILLIS: Long = 1_700_000_000_000L
    }
}

internal fun interface StoreFactory {
    fun create(clock: ServerClock): ChallengeStore
}

internal class ContractViolation(message: String) : AssertionError(message)

internal class Check(val name: String, val run: (StoreFactory) -> Unit)

private const val SESSION = "session-a"
private const val OTHER_SESSION = "session-b"

private fun ChallengeStore.redeemOrdinary(value: String?, session: String = SESSION) =
    redeem(value, session, ChallengePurpose.ORDINARY_USE)

private fun expectRejected(result: RedemptionResult, reason: RedemptionFailure, what: String) {
    if (result !is RedemptionResult.Rejected) {
        throw ContractViolation("$what: expected rejection with $reason, got $result")
    }
    if (result.reason != reason) {
        throw ContractViolation("$what: expected $reason, got ${result.reason}")
    }
}

private fun expectAccepted(result: RedemptionResult, what: String): Challenge {
    if (result !is RedemptionResult.Accepted) {
        throw ContractViolation("$what: expected acceptance, got $result")
    }
    return result.challenge
}

internal object ChallengeContract {

    /** Properties a permissive store cannot satisfy. Each must reject something. */
    val rejections: List<Check> = listOf(
        Check("a challenge the server never issued is rejected") { factory ->
            val store = factory.create(MutableClock())
            expectRejected(
                store.redeemOrdinary("not-a-challenge-we-minted"),
                RedemptionFailure.UNKNOWN_CHALLENGE,
                "unknown challenge"
            )
        },

        Check("a report carrying no challenge is rejected, not treated as unbound-but-fine") { factory ->
            val store = factory.create(MutableClock())
            store.issue(SESSION, ChallengePurpose.ORDINARY_USE)
            expectRejected(
                store.redeemOrdinary(null),
                RedemptionFailure.REPORT_NOT_BOUND,
                "null challenge"
            )
        },

        Check("an expired challenge is rejected") { factory ->
            val clock = MutableClock()
            val store = factory.create(clock)
            val issued = store.issue(SESSION, ChallengePurpose.ORDINARY_USE)
            clock.advanceBy(issued.expiresAtMillis - issued.issuedAtMillis + 1)
            expectRejected(
                store.redeemOrdinary(issued.value),
                RedemptionFailure.EXPIRED,
                "expired challenge"
            )
        },

        Check("a challenge is expired at exactly its expiry instant, not one tick later") { factory ->
            val clock = MutableClock()
            val store = factory.create(clock)
            val issued = store.issue(SESSION, ChallengePurpose.ORDINARY_USE)
            clock.advanceBy(issued.expiresAtMillis - issued.issuedAtMillis)
            expectRejected(
                store.redeemOrdinary(issued.value),
                RedemptionFailure.EXPIRED,
                "challenge at its expiry instant"
            )
        },

        Check("a challenge cannot be redeemed twice") { factory ->
            val store = factory.create(MutableClock())
            val issued = store.issue(SESSION, ChallengePurpose.ORDINARY_USE)
            expectAccepted(store.redeemOrdinary(issued.value), "first redemption")
            expectRejected(
                store.redeemOrdinary(issued.value),
                RedemptionFailure.ALREADY_REDEEMED,
                "second redemption"
            )
        },

        Check("a captured report replayed after its challenge was spent is rejected") { factory ->
            val store = factory.create(MutableClock())
            // The attacker records a legitimate submission...
            val issued = store.issue(SESSION, ChallengePurpose.ORDINARY_USE)
            expectAccepted(store.redeemOrdinary(issued.value), "the genuine submission")
            // ...obtains their own fresh challenge, and replays the captured clean report,
            // which still echoes the old challenge. Minting a new challenge does not help
            // them, because the report is bound to the one it was produced for.
            store.issue(SESSION, ChallengePurpose.ORDINARY_USE)
            expectRejected(
                store.redeemOrdinary(issued.value),
                RedemptionFailure.ALREADY_REDEEMED,
                "replayed report"
            )
        },

        Check("a challenge issued to one session cannot be redeemed by another") { factory ->
            val store = factory.create(MutableClock())
            val issued = store.issue(SESSION, ChallengePurpose.ORDINARY_USE)
            expectRejected(
                store.redeemOrdinary(issued.value, session = OTHER_SESSION),
                RedemptionFailure.SESSION_MISMATCH,
                "cross-session redemption"
            )
        },

        Check("an ordinary-use challenge cannot satisfy a sensitive action") { factory ->
            val store = factory.create(MutableClock())
            val issued = store.issue(SESSION, ChallengePurpose.ORDINARY_USE)
            expectRejected(
                store.redeem(issued.value, SESSION, ChallengePurpose.SENSITIVE_ACTION),
                RedemptionFailure.PURPOSE_MISMATCH,
                "ordinary challenge presented for a sensitive action"
            )
        },

        Check("a spent challenge stays spent even for a different purpose") { factory ->
            val store = factory.create(MutableClock())
            val issued = store.issue(SESSION, ChallengePurpose.SENSITIVE_ACTION)
            expectAccepted(
                store.redeem(issued.value, SESSION, ChallengePurpose.SENSITIVE_ACTION),
                "first sensitive redemption"
            )
            expectRejected(
                store.redeemOrdinary(issued.value),
                RedemptionFailure.ALREADY_REDEEMED,
                "spent challenge re-presented as ordinary"
            )
        }
    )

    /** Properties a store that refuses everything cannot satisfy. Each must accept something. */
    val acceptances: List<Check> = listOf(
        Check("a freshly issued challenge is accepted exactly once") { factory ->
            val store = factory.create(MutableClock())
            val issued = store.issue(SESSION, ChallengePurpose.ORDINARY_USE)
            val redeemed = expectAccepted(store.redeemOrdinary(issued.value), "fresh challenge")
            if (redeemed.value != issued.value) {
                throw ContractViolation("redeemed a different challenge than was issued")
            }
        },

        Check("a challenge one millisecond before expiry is still accepted") { factory ->
            val clock = MutableClock()
            val store = factory.create(clock)
            val issued = store.issue(SESSION, ChallengePurpose.ORDINARY_USE)
            clock.advanceBy(issued.expiresAtMillis - issued.issuedAtMillis - 1)
            expectAccepted(store.redeemOrdinary(issued.value), "challenge just before expiry")
        },

        Check("a sensitive-action challenge satisfies a sensitive action") { factory ->
            val store = factory.create(MutableClock())
            val issued = store.issue(SESSION, ChallengePurpose.SENSITIVE_ACTION)
            expectAccepted(
                store.redeem(issued.value, SESSION, ChallengePurpose.SENSITIVE_ACTION),
                "sensitive challenge for a sensitive action"
            )
        },

        Check("two sessions redeem their own challenges independently") { factory ->
            val store = factory.create(MutableClock())
            val a = store.issue(SESSION, ChallengePurpose.ORDINARY_USE)
            val b = store.issue(OTHER_SESSION, ChallengePurpose.ORDINARY_USE)
            expectAccepted(store.redeemOrdinary(a.value), "session a")
            expectAccepted(store.redeemOrdinary(b.value, session = OTHER_SESSION), "session b")
        }
    )

    val all: List<Check> get() = rejections + acceptances
}
