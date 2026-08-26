package io.integrity.sample.backend

import com.google.common.truth.Truth.assertThat
import io.integrity.core.Verdict
import org.junit.Test

class VerificationServiceTest {

    private val clock = MutableClock()

    // --- Client advisory cannot influence the decision --------------------------------

    @Test
    fun `the decision is byte-identical whatever the client claims about itself`() {
        // The strongest form of "the client verdict is ignored": not "a lying advisory is
        // rejected", but that the advisory is not an input at all. Anything it could say
        // produces the same answer, so there is nothing to lie with.
        val advisories = listOf(
            null,
            ADVISORY_LYING,
            ADVISORY_PANICKING,
            ClientAdvisory(Verdict.UNKNOWN, Int.MAX_VALUE, Int.MAX_VALUE),
            ClientAdvisory(Verdict.LOW_RISK, -1, -1)
        )
        val decisions = advisories.map { advisory ->
            val service = service(clock)
            val challenge = service.issueChallenge(SESSION)
            service.submit(challenge, advisory = advisory).copy(challenge = null, expiresAtMillis = 0)
        }
        assertThat(decisions.toSet()).hasSize(1)
        assertThat(decisions.first().deviceState).isEqualTo(DeviceState.TRUSTED)
    }

    @Test
    fun `a client claiming TRUSTED over compromising signals is denied`() {
        val service = service(clock)
        val challenge = service.issueChallenge(SESSION)
        val decision = service.submit(
            challenge,
            signals = incriminatingSignals(),
            advisory = ADVISORY_LYING
        )
        assertThat(decision.deviceState).isNotEqualTo(DeviceState.TRUSTED)
    }

    // --- Evidence can incriminate, never exonerate ------------------------------------

    @Test
    fun `a spotless report buys nothing without attestation`() {
        // The property the whole design turns on. A clean device and a client suppressing
        // everything send the same bytes, so a clean report can never be the reason for trust.
        val service = service(clock, verifier = ScriptedVerifier { AttestationOutcome.Unavailable })
        val challenge = service.issueChallenge(SESSION)
        val decision = service.submit(challenge, signals = cleanSignals(), advisory = ADVISORY_LYING)

        assertThat(decision.deviceState).isEqualTo(DeviceState.UNAVAILABLE)
        assertThat(decision.action).isNotEqualTo(Action.ALLOW)
    }

    @Test
    fun `an empty report with verified attestation is TRUSTED, because attestation is the anchor`() {
        // The counterpart, and it must be stated rather than left implicit: an empty report is
        // the normal clean case, so it is not itself suspicious. Trust arrives from the
        // authenticated side.
        val service = service(clock)
        val decision = service.submit(service.issueChallenge(SESSION), signals = emptyList())

        assertThat(decision.deviceState).isEqualTo(DeviceState.TRUSTED)
    }

    @Test
    fun `incriminating signals outrank a clean attestation`() {
        val service = service(clock)
        val decision = service.submit(service.issueChallenge(SESSION), signals = incriminatingSignals())

        assertThat(decision.deviceState).isEqualTo(DeviceState.COMPROMISED)
        assertThat(decision.reason).isEqualTo(DecisionReason.SIGNALS_INDICATE_COMPROMISE)
    }

    @Test
    fun `a client cannot suppress evidence it already sent by claiming low coverage`() {
        // The downgrade attack the scorer's own coverage gate would otherwise open: claim you
        // barely looked, and have your own incriminating findings discarded as UNKNOWN.
        val service = service(clock)
        val decision = service.submit(
            service.issueChallenge(SESSION),
            signals = incriminatingSignals(),
            advisory = ClientAdvisory(Verdict.UNKNOWN, 0, coveragePermille = 0)
        )

        assertThat(decision.deviceState).isEqualTo(DeviceState.COMPROMISED)
    }

    @Test
    fun `inconclusive signals are not incriminating and are not exonerating`() {
        val withoutToken = service(clock, verifier = ScriptedVerifier { AttestationOutcome.Unavailable })
        assertThat(
            withoutToken.submit(withoutToken.issueChallenge(SESSION), signals = inconclusiveSignals()).deviceState
        )
            .isEqualTo(DeviceState.UNAVAILABLE)

        val withToken = service(clock)
        assertThat(withToken.submit(withToken.issueChallenge(SESSION), signals = inconclusiveSignals()).deviceState)
            .isEqualTo(DeviceState.TRUSTED)
    }

    @Test
    fun `the default policy weights no signal, so a backend must set its own`() {
        // Pins a property that is easy to be surprised by: Policy.balanced() carries no
        // weights, and score() filters to promoted signals before any escalation, so under it
        // a CONFIRMED hooking signal cannot reach COMPROMISED. If weights are ever added to
        // the default policy this fails, which is the point — someone should look again.
        val service = service(clock, policy = io.integrity.core.Policy.balanced())
        val decision = service.submit(service.issueChallenge(SESSION), signals = incriminatingSignals())

        assertThat(decision.deviceState).isEqualTo(DeviceState.TRUSTED)
    }

    // --- Attestation ------------------------------------------------------------------

    @Test
    fun `an unreachable verifier yields UNAVAILABLE, never TRUSTED`() {
        val service = service(clock, verifier = ScriptedVerifier { AttestationOutcome.Unavailable })
        val challenge = service.issueChallenge(SESSION)
        val decision = service.submit(challenge)

        assertThat(decision.deviceState).isEqualTo(DeviceState.UNAVAILABLE)
        assertThat(decision.action).isNotEqualTo(Action.ALLOW)
    }

    @Test
    fun `a missing token is treated as unavailable rather than waved through`() {
        val service = service(clock)
        val challenge = service.issueChallenge(SESSION)
        val decision = service.submit(challenge, token = null)

        assertThat(decision.deviceState).isEqualTo(DeviceState.UNAVAILABLE)
    }

    @Test
    fun `an invalid token is COMPROMISED`() {
        val service = service(clock, verifier = ScriptedVerifier { AttestationOutcome.Invalid("bad sig") })
        val challenge = service.issueChallenge(SESSION)

        assertThat(service.submit(challenge).deviceState).isEqualTo(DeviceState.COMPROMISED)
    }

    @Test
    fun `an unrecognised app is COMPROMISED`() {
        val service = service(
            clock,
            verifier = ScriptedVerifier {
                AttestationOutcome.Verified(
                    appRecognised = false,
                    deviceRecognised = true,
                    requestHash = RequestHash.of(it)
                )
            }
        )
        val challenge = service.issueChallenge(SESSION)
        val decision = service.submit(challenge)

        assertThat(decision.deviceState).isEqualTo(DeviceState.COMPROMISED)
        assertThat(decision.reason).isEqualTo(DecisionReason.APP_NOT_RECOGNISED)
    }

    @Test
    fun `a token bound to a different challenge is rejected`() {
        // The mix-and-match attack: a genuine token from one session paired with a report
        // answering another. requestHash is what stops it.
        val service = service(
            clock,
            verifier = ScriptedVerifier {
                AttestationOutcome.Verified(true, true, RequestHash.of("a-different-challenge"))
            }
        )
        val challenge = service.issueChallenge(SESSION)
        val decision = service.submit(challenge)

        assertThat(decision.deviceState).isEqualTo(DeviceState.COMPROMISED)
        assertThat(decision.reason).isEqualTo(DecisionReason.REQUEST_HASH_MISMATCH)
    }

    @Test
    fun `an unrecognised device is COMPROMISED`() {
        // Found by mutation, not by review: the branch existed and nothing exercised it, so
        // deleting it changed no test result.
        val service = service(
            clock,
            verifier = ScriptedVerifier {
                AttestationOutcome.Verified(
                    appRecognised = true,
                    deviceRecognised = false,
                    requestHash = RequestHash.of(it)
                )
            }
        )
        val decision = service.submit(service.issueChallenge(SESSION))

        assertThat(decision.deviceState).isEqualTo(DeviceState.COMPROMISED)
        assertThat(decision.reason).isEqualTo(DecisionReason.DEVICE_NOT_RECOGNISED)
    }

    @Test
    fun `a token with no requestHash at all is rejected`() {
        val service = service(
            clock,
            verifier = ScriptedVerifier {
                AttestationOutcome.Verified(true, true, requestHash = null)
            }
        )
        assertThat(service.submit(service.issueChallenge(SESSION)).reason)
            .isEqualTo(DecisionReason.REQUEST_HASH_MISMATCH)
    }

    // --- Freshness is the server's ----------------------------------------------------

    @Test
    fun `a client cannot extend the decision window`() {
        val service = service(clock)
        val challenge = service.issueChallenge(SESSION)
        val decision = service.submit(challenge, requestedMaxAgeMillis = A_YEAR)

        assertThat(decision.expiresAtMillis - clock.nowMillis())
            .isEqualTo(DecisionPolicy.ORDINARY_WINDOW_MILLIS)
    }

    @Test
    fun `a client can shorten the decision window`() {
        val service = service(clock)
        val challenge = service.issueChallenge(SESSION)
        val decision = service.submit(challenge, requestedMaxAgeMillis = ONE_MINUTE)

        assertThat(decision.expiresAtMillis - clock.nowMillis()).isEqualTo(ONE_MINUTE)
    }

    @Test
    fun `a negative requested window cannot produce a decision that outlives the server's`() {
        val service = service(clock)
        val challenge = service.issueChallenge(SESSION)
        val decision = service.submit(challenge, requestedMaxAgeMillis = -A_YEAR)

        assertThat(decision.expiresAtMillis).isAtMost(clock.nowMillis() + DecisionPolicy.ORDINARY_WINDOW_MILLIS)
        assertThat(decision.expiresAtMillis).isAtLeast(clock.nowMillis())
    }

    @Test
    fun `expiry is measured from the server clock, not the report's timestamp`() {
        val service = service(clock)
        val challenge = service.issueChallenge(SESSION)
        val submission = ReportSubmission(
            sessionId = SESSION,
            report = report(challenge.value, generatedAtMillis = clock.nowMillis() + A_YEAR),
            playIntegrityToken = challenge.value
        )
        val decision = service.verify(submission)

        assertThat(decision.expiresAtMillis)
            .isEqualTo(clock.nowMillis() + DecisionPolicy.ORDINARY_WINDOW_MILLIS)
    }

    // --- Binding, purpose and replay --------------------------------------------------

    @Test
    fun `the decision records the challenge and purpose it answers`() {
        val service = service(clock)
        val challenge = service.issueChallenge(SESSION, ChallengePurpose.SENSITIVE_ACTION)
        val decision = service.submit(challenge, purpose = ChallengePurpose.SENSITIVE_ACTION)

        assertThat(decision.challenge).isEqualTo(challenge.value)
        assertThat(decision.purpose).isEqualTo(ChallengePurpose.SENSITIVE_ACTION)
    }

    @Test
    fun `an ordinary decision cannot be used for a sensitive action`() {
        val service = service(clock)
        val ordinary = service.issueChallenge(SESSION, ChallengePurpose.ORDINARY_USE)
        val decision = service.submit(ordinary, purpose = ChallengePurpose.SENSITIVE_ACTION)

        assertThat(decision.action).isEqualTo(Action.DENY)
        assertThat(decision.reason).isEqualTo(DecisionReason.CHALLENGE_REJECTED)
    }

    @Test
    fun `a sensitive decision gets a shorter window than an ordinary one`() {
        val service = service(clock)
        val sensitive = service.issueChallenge(SESSION, ChallengePurpose.SENSITIVE_ACTION)
        val decision = service.submit(sensitive, purpose = ChallengePurpose.SENSITIVE_ACTION)

        assertThat(decision.expiresAtMillis - clock.nowMillis())
            .isEqualTo(DecisionPolicy.SENSITIVE_WINDOW_MILLIS)
        assertThat(DecisionPolicy.SENSITIVE_WINDOW_MILLIS)
            .isLessThan(DecisionPolicy.ORDINARY_WINDOW_MILLIS)
    }

    @Test
    fun `a replayed submission is denied and carries no window`() {
        val service = service(clock)
        val challenge = service.issueChallenge(SESSION)
        assertThat(service.submit(challenge).action).isEqualTo(Action.ALLOW)

        val replay = service.submit(challenge)
        assertThat(replay.action).isEqualTo(Action.DENY)
        assertThat(replay.reason).isEqualTo(DecisionReason.CHALLENGE_REJECTED)
        assertThat(replay.expiresAtMillis).isAtMost(clock.nowMillis())
        assertThat(replay.challenge).isNull()
    }

    @Test
    fun `sensitive policy is never weaker than ordinary for any device state`() {
        val policy = DecisionPolicy()
        DeviceState.entries.forEach { state ->
            val ordinary = policy.actionFor(state, ChallengePurpose.ORDINARY_USE)
            val sensitive = policy.actionFor(state, ChallengePurpose.SENSITIVE_ACTION)
            assertThat(STRICTNESS.indexOf(sensitive)).isAtLeast(STRICTNESS.indexOf(ordinary))
        }
    }

    @Test
    fun `an unmapped device state denies rather than allows`() {
        val policy = DecisionPolicy(ordinaryActions = emptyMap(), sensitiveActions = emptyMap())
        DeviceState.entries.forEach { state ->
            assertThat(policy.actionFor(state, ChallengePurpose.ORDINARY_USE)).isEqualTo(Action.DENY)
        }
    }

    // --- The stub must not ship -------------------------------------------------------

    @Test
    fun `a production service refuses a verifier that does not talk to Google`() {
        val error = runCatching {
            VerificationService.forProduction(
                challenges = InMemoryChallengeStore(clock),
                verifier = verifierEchoing(),
                scorer = io.integrity.core.RiskScorer(io.integrity.core.Policy.balanced()),
                decisionPolicy = DecisionPolicy(),
                clock = clock
            )
        }.exceptionOrNull()

        assertThat(error).isInstanceOf(IllegalArgumentException::class.java)
        assertThat(error).hasMessageThat().contains("NotForProduction")
    }

    private companion object {
        const val SESSION = "session-a"
        const val ONE_MINUTE = 60_000L
        const val A_YEAR = 365L * 24 * 60 * 60 * 1000
        val STRICTNESS = listOf(Action.ALLOW, Action.STEP_UP, Action.REVIEW, Action.DENY)
    }
}
