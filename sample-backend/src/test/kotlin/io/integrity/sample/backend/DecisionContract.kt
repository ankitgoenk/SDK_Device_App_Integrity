package io.integrity.sample.backend

import io.integrity.core.Signal

/**
 * A scenario the decision pipeline must handle, described independently of how it is run.
 *
 * Indirection with a purpose: the same scenarios drive the real pipeline and a deliberately
 * permissive one, so the negative properties can be shown to have teeth rather than assumed to.
 */
internal data class Scenario(
    val signals: List<Signal> = cleanSignals(),
    val attestation: (String) -> AttestationOutcome = { token ->
        AttestationOutcome.Verified(true, true, RequestHash.of(token))
    },
    val sendToken: Boolean = true,
    val purpose: ChallengePurpose = ChallengePurpose.ORDINARY_USE,
    val requiredPurpose: ChallengePurpose = ChallengePurpose.ORDINARY_USE,
    val replay: Boolean = false,
    val advisory: ClientAdvisory? = null
)

internal fun interface DecisionHarness {
    fun decide(scenario: Scenario): Decision
}

internal class DecisionCheck(val name: String, val run: (DecisionHarness) -> Unit)

/** Runs a scenario against the real service. */
internal fun realHarness(): DecisionHarness = DecisionHarness { scenario ->
    val clock = MutableClock()
    val service = service(clock, verifier = ScriptedVerifier(scenario.attestation))
    val challenge = service.issueChallenge(SESSION_ID, scenario.purpose)
    val first = service.submit(
        challenge,
        signals = scenario.signals,
        advisory = scenario.advisory,
        token = if (scenario.sendToken) challenge.value else null,
        purpose = scenario.requiredPurpose
    )
    if (!scenario.replay) {
        first
    } else {
        service.submit(
            challenge,
            signals = scenario.signals,
            token = if (scenario.sendToken) challenge.value else null,
            purpose = scenario.requiredPurpose
        )
    }
}

internal const val SESSION_ID = "session-a"

private fun refuse(what: String, decision: Decision): Nothing =
    throw ContractViolation("$what: expected something other than an allow, got $decision")

private fun expectNotAllowed(decision: Decision, what: String) {
    if (decision.action == Action.ALLOW || decision.deviceState == DeviceState.TRUSTED) {
        refuse(what, decision)
    }
}

/**
 * The decision properties that must hold no matter what the client sends.
 *
 * Every one is a refusal, which is the point: a pipeline that allows everything must fail all
 * of them. The positive cases live in [VerificationServiceTest], where they belong — mixing
 * them in here would let a permissive implementation score partial credit.
 */
internal object DecisionContract {

    val refusals: List<DecisionCheck> = listOf(
        DecisionCheck("a report with no attestation is not trusted") {
            expectNotAllowed(
                it.decide(Scenario(sendToken = false)),
                "missing token"
            )
        },
        DecisionCheck("an unreachable attestation service is not trusted") {
            expectNotAllowed(
                it.decide(Scenario(attestation = { AttestationOutcome.Unavailable })),
                "attestation unavailable"
            )
        },
        DecisionCheck("an invalid token is not trusted") {
            expectNotAllowed(
                it.decide(Scenario(attestation = { AttestationOutcome.Invalid("bad") })),
                "invalid token"
            )
        },
        DecisionCheck("an unrecognised app is not trusted") {
            expectNotAllowed(
                it.decide(
                    Scenario(attestation = { AttestationOutcome.Verified(false, true, RequestHash.of(it)) })
                ),
                "app not recognised"
            )
        },
        DecisionCheck("a token bound to another challenge is not trusted") {
            expectNotAllowed(
                it.decide(
                    Scenario(attestation = { AttestationOutcome.Verified(true, true, RequestHash.of("elsewhere")) })
                ),
                "requestHash mismatch"
            )
        },
        DecisionCheck("incriminating signals are not trusted") {
            expectNotAllowed(
                it.decide(Scenario(signals = incriminatingSignals())),
                "incriminating signals"
            )
        },
        DecisionCheck("a client claiming to be clean over its own bad signals is not trusted") {
            expectNotAllowed(
                it.decide(
                    Scenario(signals = incriminatingSignals(), advisory = ADVISORY_LYING)
                ),
                "lying advisory"
            )
        },
        DecisionCheck("a replayed submission is not trusted") {
            expectNotAllowed(it.decide(Scenario(replay = true)), "replay")
        },
        DecisionCheck("an ordinary challenge does not satisfy a sensitive action") {
            expectNotAllowed(
                it.decide(
                    Scenario(
                        purpose = ChallengePurpose.ORDINARY_USE,
                        requiredPurpose = ChallengePurpose.SENSITIVE_ACTION
                    )
                ),
                "ordinary challenge for a sensitive action"
            )
        }
    )
}
