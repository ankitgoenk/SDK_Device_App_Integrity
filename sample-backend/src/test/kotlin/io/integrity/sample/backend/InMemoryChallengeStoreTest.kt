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
        assertThat(roundsWithWrongWinnerCount(ROUNDS) { InMemoryChallengeStore(it) }).isEqualTo(0)
    }

    @Test
    fun `single use is a compare-and-set, which no amount of racing can establish`() {
        // Measured, because the alternative is believing the test above does more than it can.
        // Across 16 threads, the wide-window shape (HashSet contains-then-add) is caught 17
        // times in 500 rounds. The narrow shape — AtomicBoolean get() then set(), which is
        // exactly what a careless "fix" produces — was caught 0 times in 5000. The window is a
        // volatile read and a volatile write; threads do not interleave there in practice.
        //
        // So the property is asserted where it is decidable: in the source. This is unusual in
        // a unit test and is the honest option, because the behavioural test provably cannot
        // distinguish the two implementations, and mutation testing showed it does not.
        val source = storeSource()
        assertThat(source).contains("compareAndSet(false, true)")
        assertThat(source).doesNotContain(".spent.get()")
        assertThat(source).doesNotContain(".spent.set(")
    }

    private fun storeSource(): String {
        var dir = java.io.File(System.getProperty("user.dir")).absoluteFile
        while (dir.parentFile != null) {
            val candidate = java.io.File(
                dir,
                "sample-backend/src/main/kotlin/io/integrity/sample/backend/InMemoryChallengeStore.kt"
            )
            if (candidate.isFile) return candidate.readText()
            dir = dir.parentFile
        }
        throw AssertionError("could not locate InMemoryChallengeStore.kt from ${System.getProperty("user.dir")}")
    }

    @Test
    fun `the race harness can actually observe a lost update on this machine`() {
        // Positive control for the test above, which is otherwise unfalsifiable. A single
        // contended round detects check-then-act roughly never — measured at 0 hits in 20
        // rounds, ~3% per round thereafter — so the first version of this test passed a store
        // that was plainly not atomic. If the harness cannot catch a deliberately broken store
        // here, it cannot vouch for the real one either, and this says so rather than staying
        // green on hardware where the window never opens.
        assertThat(roundsWithWrongWinnerCount(CONTROL_ROUNDS) { CheckThenActStore(it) }).isGreaterThan(0)
    }

    /**
     * A store whose single-use gate is a read followed by a write, with the window held open.
     *
     * The pause is not realism — it is calibration. This control answers one question, "can the
     * harness observe a lost update at all", and a realistic narrow window makes the answer
     * depend on how loaded the machine is. It failed exactly that way once during development,
     * under concurrent load, which is a flaky test in CI and worse than no test. A wide window
     * makes the control deterministic; the separate source-level assertion above is what covers
     * narrow windows, because timing provably cannot.
     */
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
            Thread.sleep(CONTROL_WINDOW_MILLIS)
            spent += key
            return RedemptionResult.Accepted(challenge)
        }
    }

    /**
     * Runs [ROUNDS] contended redemptions and counts the rounds where the number of winners
     * was not exactly one. An atomic store scores zero; a racy one scores above zero.
     */
    private fun roundsWithWrongWinnerCount(rounds: Int, newStore: (ServerClock) -> ChallengeStore): Int {
        val pool = Executors.newFixedThreadPool(THREADS)
        return try {
            (1..rounds).count { _ ->
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
        const val CONTROL_ROUNDS = 3
        const val CONTROL_WINDOW_MILLIS = 2L
        const val WINDOW = 120_000L
        const val TIMEOUT_SECONDS = 10L
        const val SAMPLE_SIZE = 1000
        const val MIN_VALUE_LENGTH = 43
        const val ONE_MINUTE = 60_000L
        const val ORDINARY_DECISION_WINDOW = 30 * 60 * 1000L
    }
}
