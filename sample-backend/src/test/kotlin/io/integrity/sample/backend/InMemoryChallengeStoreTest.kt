package io.integrity.sample.backend

import com.google.common.truth.Truth.assertThat
import java.util.concurrent.Callable
import java.util.concurrent.CyclicBarrier
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.junit.Test

class InMemoryChallengeStoreTest {

    private val factory = StoreFactory { clock -> InMemoryChallengeStore(clock) }

    @Test
    fun `satisfies every challenge-lifecycle property`() {
        val failures = ChallengeContract.all.mapNotNull { check ->
            runCatching { check.run(factory) }.exceptionOrNull()?.let { "${check.name}: ${it.message}" }
        }
        assertThat(failures).isEmpty()
    }

    // --- Properties specific to this implementation ------------------------------------

    @Test
    fun `exactly one of many concurrent redemptions of the same challenge succeeds`() {
        assertThat(roundsWithWrongWinnerCount { InMemoryChallengeStore(it) }).isEqualTo(0)
    }

    @Test
    fun `the race harness can actually observe a lost update on this machine`() {
        // Positive control for the test above, which is otherwise unfalsifiable. A single
        // contended round detects check-then-act roughly never — measured at 0 hits in 20
        // rounds, ~3% per round thereafter — so the first version of this test passed a store
        // that was plainly not atomic. If the harness cannot catch a deliberately broken store
        // here, it cannot vouch for the real one either, and this says so rather than staying
        // green on hardware where the window never opens.
        assertThat(roundsWithWrongWinnerCount { CheckThenActStore(it) }).isGreaterThan(0)
    }

    /** A store whose single-use gate is a read followed by a write. The bug, on purpose. */
    private class CheckThenActStore(private val clock: ServerClock) : ChallengeStore {
        private val issued = mutableMapOf<String, Challenge>()
        private val spent = mutableSetOf<String>()

        override fun issue(sessionId: String, purpose: ChallengePurpose): Challenge {
            val now = clock.nowMillis()
            val challenge = Challenge("c" + issued.size, purpose, sessionId, now, now + WINDOW)
            issued[challenge.value] = challenge
            return challenge
        }

        override fun redeem(
            reportChallenge: String?,
            sessionId: String,
            requiredPurpose: ChallengePurpose
        ): RedemptionResult {
            val key = reportChallenge
                ?: return RedemptionResult.Rejected(RedemptionFailure.REPORT_NOT_BOUND)
            val challenge = issued[key]
                ?: return RedemptionResult.Rejected(RedemptionFailure.UNKNOWN_CHALLENGE)
            if (key in spent) {
                return RedemptionResult.Rejected(RedemptionFailure.ALREADY_REDEEMED)
            }
            spent += key
            return RedemptionResult.Accepted(challenge)
        }
    }

    /**
     * Runs [ROUNDS] contended redemptions and counts the rounds where the number of winners
     * was not exactly one. An atomic store scores zero; a racy one scores above zero.
     */
    private fun roundsWithWrongWinnerCount(newStore: (ServerClock) -> ChallengeStore): Int {
        val pool = Executors.newFixedThreadPool(THREADS)
        return try {
            (1..ROUNDS).count { _ ->
                val store = newStore(MutableClock())
                val issued = store.issue(SESSION, ChallengePurpose.ORDINARY_USE)
                val barrier = CyclicBarrier(THREADS)
                val winners = pool.invokeAll(
                    (1..THREADS).map {
                        Callable {
                            barrier.await(TIMEOUT_SECONDS, TimeUnit.SECONDS)
                            store.redeem(issued.value, SESSION, ChallengePurpose.ORDINARY_USE)
                        }
                    }
                ).count { it.get(TIMEOUT_SECONDS, TimeUnit.SECONDS) is RedemptionResult.Accepted }
                winners != 1
            }
        } finally {
            pool.shutdownNow()
        }
    }

    @Test
    fun `issued values are unpredictable and never repeat`() {
        val store = InMemoryChallengeStore(MutableClock())
        val values = (1..SAMPLE_SIZE).map { store.issue(SESSION, ChallengePurpose.ORDINARY_USE).value }

        assertThat(values.toSet()).hasSize(SAMPLE_SIZE)
        // Enough entropy that guessing is not a strategy. 32 bytes base64url-encodes to 43
        // characters with no padding.
        values.forEach { assertThat(it.length).isAtLeast(MIN_VALUE_LENGTH) }
        // Not derived from the session: two challenges for one session must differ.
        assertThat(values[0]).isNotEqualTo(values[1])
    }

    @Test
    fun `expiry is derived from the server clock at issue time`() {
        val clock = MutableClock()
        val store = InMemoryChallengeStore(clock)

        val first = store.issue(SESSION, ChallengePurpose.ORDINARY_USE)
        assertThat(first.expiresAtMillis - first.issuedAtMillis)
            .isEqualTo(InMemoryChallengeStore.DEFAULT_TTL_MILLIS)

        clock.advanceBy(ONE_MINUTE)
        val second = store.issue(SESSION, ChallengePurpose.ORDINARY_USE)
        assertThat(second.issuedAtMillis - first.issuedAtMillis).isEqualTo(ONE_MINUTE)
    }

    @Test
    fun `the ttl is the challenge window and not the decision window`() {
        // ADR-0006 keeps these apart deliberately: 30 minutes is how long a *decision* is good
        // for, and a challenge that lived that long would widen the replay window by two orders
        // of magnitude for no benefit. If someone "unifies" these constants, this fails.
        assertThat(InMemoryChallengeStore.DEFAULT_TTL_MILLIS).isLessThan(ORDINARY_DECISION_WINDOW)
    }

    private companion object {
        const val SESSION = "session-a"
        const val THREADS = 16
        const val ROUNDS = 500
        const val WINDOW = 120_000L
        const val TIMEOUT_SECONDS = 10L
        const val SAMPLE_SIZE = 1000
        const val MIN_VALUE_LENGTH = 43
        const val ONE_MINUTE = 60_000L
        const val ORDINARY_DECISION_WINDOW = 30 * 60 * 1000L
    }
}
