package io.integrity.sample.backend

import com.google.common.truth.Truth.assertThat
import io.integrity.core.Verdict
import org.junit.Test

class VerificationServiceTest {

    private val clock = MutableClock()

    // --- There is no route to trust ---------------------------------------------------

    @Test
    fun `the vocabulary contains no trusted state at all`() {
        // A shape assertion rather than a behavioural one, and deliberately so: every
        // behavioural test can only sample inputs, and the property here is about the
        // codomain. Adding TRUSTED back fails this immediately, which sends whoever did it to
        // ADR-0008 before they wire it to anything.
        assertThat(DeviceState.entries).containsExactly(
            DeviceState.COMPROMISED,
            DeviceState.NO_EVIDENCE_OF_COMPROMISE,
            DeviceState.INSUFFICIENT_EVIDENCE
        )
    }

    @Test
    fun `nothing a client can send produces a finding stronger than an absence of evidence`() {
        // The ceiling, sampled across everything a client controls. Combined with the shape
        // assertion above, this is the whole of "evidence can never exonerate".
        val service = service(clock)
        val signalSets = listOf(cleanSignals(), inconclusiveSignals(), incriminatingSignals())
        val advisories = listOf(null, ADVISORY_LYING, ADVISORY_PANICKING)

        signalSets.forEach { signals ->
            advisories.forEach { advisory ->
                val decision = service.submit(service.issueChallenge(SESSION), signals, advisory)
                assertThat(decision.deviceState).isAnyOf(
                    DeviceState.COMPROMISED,
                    DeviceState.NO_EVIDENCE_OF_COMPROMISE
                )
            }
        }
    }

    // --- Client advisory cannot influence the finding ---------------------------------

    @Test
    fun `the finding is byte-identical whatever the client claims about itself`() {
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
        assertThat(decisions.first().deviceState).isEqualTo(DeviceState.NO_EVIDENCE_OF_COMPROMISE)
    }

    @Test
    fun `a client claiming to be clean over compromising signals is still compromised`() {
        val service = service(clock)
        val decision = service.submit(
            service.issueChallenge(SESSION),
            signals = incriminatingSignals(),
            advisory = ADVISORY_LYING
        )
        assertThat(decision.deviceState).isEqualTo(DeviceState.COMPROMISED)
    }

    // --- Evidence can incriminate, never exonerate ------------------------------------

    @Test
    fun `a spotless report yields an absence of evidence, which is not a pass`() {
        // The property the whole design turns on. A clean device and a client suppressing
        // everything send the same bytes, so a clean report can never be the reason for trust.
        // What it earns is a named absence the caller has to combine with something else.
        val service = service(clock)
        val decision = service.submit(service.issueChallenge(SESSION), signals = cleanSignals())

        assertThat(decision.deviceState).isEqualTo(DeviceState.NO_EVIDENCE_OF_COMPROMISE)
        assertThat(decision.reason).isEqualTo(DecisionReason.NO_SIGNAL_INCRIMINATES)
    }

    @Test
    fun `incriminating signals are believed`() {
        val service = service(clock)
        val decision = service.submit(service.issueChallenge(SESSION), signals = incriminatingSignals())

        assertThat(decision.deviceState).isEqualTo(DeviceState.COMPROMISED)
        assertThat(decision.reason).isEqualTo(DecisionReason.SIGNALS_INDICATE_COMPROMISE)
    }

    @Test
    fun `a suspicious score incriminates, and a low-risk one does not`() {
        // Both sides of the bar, in one test so the boundary cannot drift unnoticed.
        //
        // The SUSPICIOUS half is here because mutation testing found it missing: dropping
        // `|| verdict == SUSPICIOUS` from the pipeline changed no test result. Everything
        // incriminating in the suite scored COMPROMISED outright, so half the predicate was
        // decorative — on the one code path that, since ADR-0008, decides every finding.
        val service = service(clock)

        val suspicious = service.submit(service.issueChallenge(SESSION), signals = suspiciousSignals())
        assertThat(suspicious.deviceState).isEqualTo(DeviceState.COMPROMISED)
        assertThat(suspicious.reason).isEqualTo(DecisionReason.SIGNALS_INDICATE_COMPROMISE)

        val lowRisk = service.submit(service.issueChallenge(SESSION), signals = lowRiskSignals())
        assertThat(lowRisk.deviceState).isEqualTo(DeviceState.NO_EVIDENCE_OF_COMPROMISE)
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
        val service = service(clock)
        val inconclusive = service.submit(service.issueChallenge(SESSION), signals = inconclusiveSignals())
        val clean = service.submit(service.issueChallenge(SESSION), signals = cleanSignals())

        // Same finding either way: "we could not tell" and "we saw nothing" are the same
        // absence as far as anything this service can conclude goes.
        assertThat(inconclusive.deviceState).isEqualTo(DeviceState.NO_EVIDENCE_OF_COMPROMISE)
        assertThat(clean.deviceState).isEqualTo(inconclusive.deviceState)
    }

    @Test
    fun `the default policy weights no signal, so a backend must set its own`() {
        // Pins a property that is easy to be surprised by: Policy.balanced() carries no
        // weights, and score() filters to promoted signals before any escalation, so under it
        // a CONFIRMED hooking signal cannot reach COMPROMISED. If weights are ever added to
        // the default policy this fails, which is the point — someone should look again.
        //
        // It matters more now than it did. With attestation gone this scoring path is the
        // only thing that can produce a finding at all, so a backend that ships balanced()
        // has a pipeline that reports every device as unremarkable.
        val service = service(clock, policy = io.integrity.core.Policy.balanced())
        val decision = service.submit(service.issueChallenge(SESSION), signals = incriminatingSignals())

        assertThat(decision.deviceState).isEqualTo(DeviceState.NO_EVIDENCE_OF_COMPROMISE)
    }

    // --- Freshness is the server's ----------------------------------------------------

    @Test
    fun `a client cannot extend the window`() {
        val service = service(clock)
        val decision = service.submit(service.issueChallenge(SESSION), requestedMaxAgeMillis = A_YEAR)

        assertThat(decision.expiresAtMillis - clock.nowMillis())
            .isEqualTo(DecisionPolicy.ORDINARY_WINDOW_MILLIS)
    }

    @Test
    fun `a client can shorten the window`() {
        val service = service(clock)
        val decision = service.submit(service.issueChallenge(SESSION), requestedMaxAgeMillis = ONE_MINUTE)

        assertThat(decision.expiresAtMillis - clock.nowMillis()).isEqualTo(ONE_MINUTE)
    }

    @Test
    fun `a negative requested window cannot produce a finding that outlives the server's`() {
        val service = service(clock)
        val decision = service.submit(service.issueChallenge(SESSION), requestedMaxAgeMillis = -A_YEAR)

        assertThat(decision.expiresAtMillis).isAtMost(clock.nowMillis() + DecisionPolicy.ORDINARY_WINDOW_MILLIS)
        assertThat(decision.expiresAtMillis).isAtLeast(clock.nowMillis())
    }

    @Test
    fun `expiry is measured from the server clock, not the report's timestamp`() {
        val service = service(clock)
        val challenge = service.issueChallenge(SESSION)
        val submission = ReportSubmission(
            sessionId = SESSION,
            report = report(challenge.value, generatedAtMillis = clock.nowMillis() + A_YEAR)
        )
        val decision = service.verify(submission)

        assertThat(decision.expiresAtMillis)
            .isEqualTo(clock.nowMillis() + DecisionPolicy.ORDINARY_WINDOW_MILLIS)
    }

    @Test
    fun `a sensitive finding gets a shorter window than an ordinary one`() {
        val service = service(clock)
        val sensitive = service.issueChallenge(SESSION, ChallengePurpose.SENSITIVE_ACTION)
        val decision = service.submit(sensitive, purpose = ChallengePurpose.SENSITIVE_ACTION)

        assertThat(decision.expiresAtMillis - clock.nowMillis())
            .isEqualTo(DecisionPolicy.SENSITIVE_WINDOW_MILLIS)
        assertThat(DecisionPolicy.SENSITIVE_WINDOW_MILLIS)
            .isLessThan(DecisionPolicy.ORDINARY_WINDOW_MILLIS)
    }

    // --- Binding, purpose and replay --------------------------------------------------

    @Test
    fun `the finding records the challenge and purpose it answers`() {
        val service = service(clock)
        val challenge = service.issueChallenge(SESSION, ChallengePurpose.SENSITIVE_ACTION)
        val decision = service.submit(challenge, purpose = ChallengePurpose.SENSITIVE_ACTION)

        assertThat(decision.challenge).isEqualTo(challenge.value)
        assertThat(decision.purpose).isEqualTo(ChallengePurpose.SENSITIVE_ACTION)
    }

    @Test
    fun `an ordinary challenge cannot be used for a sensitive action`() {
        val service = service(clock)
        val ordinary = service.issueChallenge(SESSION, ChallengePurpose.ORDINARY_USE)
        val decision = service.submit(ordinary, purpose = ChallengePurpose.SENSITIVE_ACTION)

        assertThat(decision.deviceState).isEqualTo(DeviceState.INSUFFICIENT_EVIDENCE)
        assertThat(decision.reason).isEqualTo(DecisionReason.CHALLENGE_REJECTED)
    }

    @Test
    fun `a replayed submission yields no finding and carries no window`() {
        val service = service(clock)
        val challenge = service.issueChallenge(SESSION)
        assertThat(service.submit(challenge).deviceState).isEqualTo(DeviceState.NO_EVIDENCE_OF_COMPROMISE)

        val replay = service.submit(challenge)
        assertThat(replay.deviceState).isEqualTo(DeviceState.INSUFFICIENT_EVIDENCE)
        assertThat(replay.reason).isEqualTo(DecisionReason.CHALLENGE_REJECTED)
        assertThat(replay.expiresAtMillis).isAtMost(clock.nowMillis())
        assertThat(replay.challenge).isNull()
    }

    @Test
    fun `a rejected challenge is not graded, however incriminating the report`() {
        // Ordering matters: binding is checked before scoring, so an unbound report does not
        // get to contribute evidence. Otherwise an attacker could inject findings about a
        // session they do not hold.
        val service = service(clock)
        val challenge = service.issueChallenge(SESSION)
        val decision = service.submit(
            challenge,
            signals = incriminatingSignals(),
            reportChallenge = "never-issued"
        )

        assertThat(decision.deviceState).isEqualTo(DeviceState.INSUFFICIENT_EVIDENCE)
        assertThat(decision.reason).isEqualTo(DecisionReason.CHALLENGE_REJECTED)
    }

    private companion object {
        const val SESSION = "session-a"
        const val ONE_MINUTE = 60_000L
        const val A_YEAR = 365L * 24 * 60 * 60 * 1000
    }
}
