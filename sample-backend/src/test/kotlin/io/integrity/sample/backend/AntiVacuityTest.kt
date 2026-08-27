package io.integrity.sample.backend

import com.google.common.truth.Truth.assertThat
import org.junit.Test

/**
 * Proves the contract suite cannot be satisfied by a store that does not think.
 *
 * The instruction this exists to honour: a verifier that returns "valid" for everything must
 * not be able to make the suite green. That is not something you can establish by reading the
 * tests, because the failure mode is a property nobody wrote down. So the broken
 * implementations are built here and run against the same checks.
 *
 * Both directions matter. A permissive store proves the rejections have teeth; a store that
 * refuses everything proves the acceptances do. Testing only the first would leave the suite
 * satisfiable by `return Rejected(EXPIRED)`.
 */
class AntiVacuityTest {

    /** Accepts anything it is handed. The verifier this project must never ship. */
    private class AlwaysAccepts(private val clock: ServerClock) : ChallengeStore {
        override fun issue(sessionId: String, purpose: ChallengePurpose): Challenge {
            val now = clock.nowMillis()
            return Challenge("permissive", purpose, sessionId, now, now + TTL)
        }

        override fun redeem(
            reportChallenge: String?,
            sessionId: String,
            requiredPurpose: ChallengePurpose
        ): RedemptionResult = RedemptionResult.Accepted(
            Challenge(
                reportChallenge.orEmpty(),
                requiredPurpose,
                sessionId,
                clock.nowMillis(),
                clock.nowMillis() + TTL
            )
        )
    }

    /** Refuses everything. Trivially "secure", and useless. */
    private class AlwaysRejects(private val clock: ServerClock) : ChallengeStore {
        override fun issue(sessionId: String, purpose: ChallengePurpose): Challenge {
            val now = clock.nowMillis()
            return Challenge("paranoid", purpose, sessionId, now, now + TTL)
        }

        override fun redeem(
            reportChallenge: String?,
            sessionId: String,
            requiredPurpose: ChallengePurpose
        ): RedemptionResult = RedemptionResult.Rejected(RedemptionFailure.UNKNOWN_CHALLENGE)
    }

    @Test
    fun `every rejection check fails against a store that accepts everything`() {
        val survivors = ChallengeContract.rejections.filter { check ->
            runCatching { check.run(StoreFactory(::AlwaysAccepts)) }.isSuccess
        }
        assertThat(survivors.map { it.name }).isEmpty()
    }

    @Test
    fun `every acceptance check fails against a store that rejects everything`() {
        val survivors = ChallengeContract.acceptances.filter { check ->
            runCatching { check.run(StoreFactory(::AlwaysRejects)) }.isSuccess
        }
        assertThat(survivors.map { it.name }).isEmpty()
    }

    @Test
    fun `every decision refusal fails against a pipeline that finds nothing wrong with anything`() {
        // The standing requirement, at the pipeline level: a verifier that returns "valid" for
        // everything must not be able to make this suite green. The permissive pipeline below
        // is that verifier taken to its conclusion — it skips the pipeline entirely and just
        // says nothing is wrong — and every refusal in the contract must catch it.
        //
        // This test is why the refusal predicate had to move when TRUSTED and ALLOW were
        // deleted (ADR-0008). A harness returning the new ceiling state must still fail all
        // nine; if the predicate had kept naming the departed vocabulary, this would pass
        // while proving nothing.
        val permissive = DecisionHarness {
            Decision(
                deviceState = DeviceState.NO_EVIDENCE_OF_COMPROMISE,
                reason = DecisionReason.NO_SIGNAL_INCRIMINATES,
                challenge = "whatever",
                purpose = ChallengePurpose.SENSITIVE_ACTION,
                expiresAtMillis = Long.MAX_VALUE
            )
        }
        val survivors = DecisionContract.refusals.filter { check ->
            runCatching { check.run(permissive) }.isSuccess
        }
        assertThat(survivors.map { it.name }).isEmpty()
    }

    @Test
    fun `the real pipeline satisfies every decision refusal`() {
        val harness = realHarness()
        val failures = DecisionContract.refusals.mapNotNull { check ->
            runCatching { check.run(harness) }.exceptionOrNull()?.let { "${check.name}: ${it.message}" }
        }
        assertThat(failures).isEmpty()
    }

    @Test
    fun `the contracts are not empty, so the checks above cannot pass by vacuity`() {
        // Guards the guard: filtering an empty list also yields an empty list.
        assertThat(ChallengeContract.rejections.size).isAtLeast(MIN_REJECTIONS)
        assertThat(ChallengeContract.acceptances.size).isAtLeast(MIN_ACCEPTANCES)
        assertThat(DecisionContract.refusals.size).isAtLeast(MIN_REFUSALS)
    }

    private companion object {
        const val TTL = 120_000L
        const val MIN_REJECTIONS = 8
        const val MIN_ACCEPTANCES = 4
        const val MIN_REFUSALS = 8
    }
}
