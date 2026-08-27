package io.integrity.sample.backend

import io.integrity.core.Signal
import io.integrity.core.Verdict

/**
 * A scenario the decision pipeline must handle, described independently of how it is run.
 *
 * Indirection with a purpose: the same scenarios drive the real pipeline and a deliberately
 * permissive one, so the negative properties can be shown to have teeth rather than assumed to.
 */
internal data class Scenario(
    val signals: List<Signal> = cleanSignals(),
    val purpose: ChallengePurpose = ChallengePurpose.ORDINARY_USE,
    val requiredPurpose: ChallengePurpose = ChallengePurpose.ORDINARY_USE,
    val replay: Boolean = false,
    val advisory: ClientAdvisory? = null,
    /** Substitutes the challenge the report claims to answer. Identity by default. */
    val reportChallenge: (Challenge) -> String? = { it.value },
    /** Substitutes the submitting session. Identity by default. */
    val sessionId: (Challenge) -> String = { it.sessionId },
    /** Time to burn between issue and submission, for expiry. */
    val advanceMillis: Long = 0L
)

internal fun interface DecisionHarness {
    fun decide(scenario: Scenario): Decision
}

internal class DecisionCheck(val name: String, val run: (DecisionHarness) -> Unit)

/** Runs a scenario against the real service. */
internal fun realHarness(): DecisionHarness = DecisionHarness { scenario ->
    val clock = MutableClock()
    val service = service(clock)
    val challenge = service.issueChallenge(SESSION_ID, scenario.purpose)
    clock.advanceBy(scenario.advanceMillis)
    fun submitOnce() = service.submit(
        challenge,
        signals = scenario.signals,
        advisory = scenario.advisory,
        purpose = scenario.requiredPurpose,
        sessionId = scenario.sessionId(challenge),
        reportChallenge = scenario.reportChallenge(challenge)
    )
    val first = submitOnce()
    if (!scenario.replay) first else submitOnce()
}

internal const val SESSION_ID = "session-a"

private fun refuse(what: String, decision: Decision): Nothing =
    throw ContractViolation("$what: expected something other than a clean finding, got $decision")

/**
 * The refusal predicate, and the single most delicate line in this file.
 *
 * It used to read `action == ALLOW || deviceState == TRUSTED`. Both are gone (ADR-0008), so
 * the compiler forced *a* rewrite — but not a correct one, and that is the exposure. Every
 * refusal below routes through this one line: point it at the wrong state and all nine go
 * green while asserting nothing, with no compile error and nothing in the diff to notice.
 *
 * So the bar moves with the vocabulary: the strongest thing this service can now say is
 * [DeviceState.NO_EVIDENCE_OF_COMPROMISE], and that is what these scenarios must not earn.
 * `AntiVacuityTest` runs the whole list against a harness that returns exactly that, and
 * every check must catch it. Both plausible wrong rewrites — naming `COMPROMISED` here, or
 * dropping the condition — were tried against it and both fail it, so that guard is real
 * rather than assumed.
 */
private fun expectNotClean(decision: Decision, what: String) {
    if (decision.deviceState == DeviceState.NO_EVIDENCE_OF_COMPROMISE) refuse(what, decision)
}

/**
 * The properties that must hold no matter what the client sends.
 *
 * Every one is a refusal, which is the point: a pipeline that waves everything through must
 * fail all of them. The positive cases live in [VerificationServiceTest], where they belong —
 * mixing them in here would let a permissive implementation score partial credit.
 *
 * Five of these once concerned attestation and are gone with it. The four that replace them
 * assert that a challenge-binding failure actually reaches the finding, which is a pipeline
 * property rather than a store one: `ChallengeContract` proves the store refuses, and these
 * prove the service does not then shrug and grade the report anyway.
 */
internal object DecisionContract {

    val refusals: List<DecisionCheck> = listOf(
        DecisionCheck("incriminating signals are not clean") {
            expectNotClean(
                it.decide(Scenario(signals = incriminatingSignals())),
                "incriminating signals"
            )
        },
        DecisionCheck("a client claiming to be clean over its own bad signals is not clean") {
            expectNotClean(
                it.decide(Scenario(signals = incriminatingSignals(), advisory = ADVISORY_LYING)),
                "lying advisory"
            )
        },
        DecisionCheck("a coverage claim cannot suppress evidence already sent") {
            // ADR-0007's named attack: claim you barely looked, and have your own findings
            // discarded by the scorer's low-coverage gate.
            expectNotClean(
                it.decide(
                    Scenario(
                        signals = incriminatingSignals(),
                        advisory = ClientAdvisory(Verdict.UNKNOWN, 0, coveragePermille = 0)
                    )
                ),
                "zero coverage claim"
            )
        },
        DecisionCheck("a replayed submission yields no finding") {
            expectNotClean(it.decide(Scenario(replay = true)), "replay")
        },
        DecisionCheck("an ordinary challenge does not satisfy a sensitive action") {
            expectNotClean(
                it.decide(
                    Scenario(
                        purpose = ChallengePurpose.ORDINARY_USE,
                        requiredPurpose = ChallengePurpose.SENSITIVE_ACTION
                    )
                ),
                "ordinary challenge for a sensitive action"
            )
        },
        DecisionCheck("a challenge the server never issued yields no finding") {
            expectNotClean(
                it.decide(Scenario(reportChallenge = { "never-issued" })),
                "unknown challenge"
            )
        },
        DecisionCheck("a report bound to no challenge yields no finding") {
            expectNotClean(
                it.decide(Scenario(reportChallenge = { null })),
                "unbound report"
            )
        },
        DecisionCheck("a challenge redeemed by another session yields no finding") {
            expectNotClean(
                it.decide(Scenario(sessionId = { "session-b" })),
                "session mismatch"
            )
        },
        DecisionCheck("an expired challenge yields no finding") {
            expectNotClean(
                it.decide(Scenario(advanceMillis = InMemoryChallengeStore.DEFAULT_TTL_MILLIS)),
                "expired challenge"
            )
        }
    )
}
