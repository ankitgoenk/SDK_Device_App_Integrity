package io.integrity.sample.backend

import com.google.common.truth.Truth.assertThat
import io.integrity.core.Category
import io.integrity.core.Confidence
import io.integrity.core.Depth
import io.integrity.core.IntegrityReport
import io.integrity.core.Policy
import io.integrity.core.ReportWire
import io.integrity.core.RiskScorer
import io.integrity.core.Signal
import io.integrity.core.SignalId
import io.integrity.core.SignedReport
import io.integrity.core.Verdict
import io.integrity.core.Weight
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import org.junit.Test

/**
 * Signature verification, and the two properties ADR-0011 exists to make true.
 *
 * The interesting assertions here are not "a good signature verifies". They are that a good
 * signature **buys nothing** and a bad one **costs no evidence** — the directions in which a
 * naive implementation of signing silently reintroduces the hole ADR-0007 closed.
 */
class ReportVerifierTest {

    // --- signing rig: plain JCE, since the Android Keystore is not present in a JVM test ---

    private fun keyPair(): KeyPair = KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec("secp256r1"))
    }.generateKeyPair()

    private fun keyIdOf(pair: KeyPair): String = MessageDigest.getInstance("SHA-256").digest(pair.public.encoded)
        .take(16)
        .joinToString("") { "%02x".format(it) }

    private fun canonicalReport(signals: List<Signal>, challenge: String?): String = ReportWire.canonicalJson(
        IntegrityReport(
            verdict = Verdict.NO_EVIDENCE_OF_COMPROMISE,
            riskScore = 0,
            categoryScores = emptyMap(),
            signals = signals,
            coverage = 1.0f,
            depth = Depth.STANDARD,
            generatedAtMillis = 0L,
            sdkVersion = "0.1.0-alpha01",
            reportId = "report-1",
            challenge = challenge
        )
    )

    private fun envelope(pair: KeyPair, canonicalJson: String, keyId: String = keyIdOf(pair)): String {
        val input = SignedReport.signingInput(
            SignedReport.Header(keyId, "io.integrity.sample", "0.1.0-alpha01"),
            canonicalJson
        )
        val signature = Signature.getInstance("SHA256withECDSA").run {
            initSign(pair.private)
            update(input.bytes)
            sign()
        }
        return SignedReport.seal(input, signature)
    }

    private fun registry(pair: KeyPair): InMemoryEnrolledKeys = InMemoryEnrolledKeys().apply {
        check(enrol(keyIdOf(pair), pair.public.encoded))
    }

    // --- the check itself ---------------------------------------------------------------

    @Test
    fun `a correctly signed envelope verifies`() {
        val pair = keyPair()
        val json = canonicalReport(emptyList(), "nonce-1")

        val check = ReportVerifier(registry(pair)).check(envelope(pair, json))

        assertThat(check).isInstanceOf(SignatureCheck.Valid::class.java)
        assertThat((check as SignatureCheck.Valid).canonicalReportJson).isEqualTo(json)
    }

    @Test
    fun `no envelope is unsigned, which is not the same as invalid`() {
        val check = ReportVerifier(registry(keyPair())).check(null)
        assertThat(check).isEqualTo(SignatureCheck.Unsigned)
    }

    @Test
    fun `a payload swapped after signing does not verify`() {
        // The whole point of signing over the received bytes: the signature is valid for the
        // report it was made over and for no other.
        val pair = keyPair()
        val original = envelope(pair, canonicalReport(emptyList(), "nonce-1"))
        val otherPayload = SignedReport.parse(
            envelope(pair, canonicalReport(emptyList(), "nonce-2"))
        )!!

        val parts = original.split(".")
        val swapped = listOf(
            parts[0],
            parts[1],
            envelope(pair, otherPayload.canonicalReportJson).split(".")[2],
            parts[3]
        ).joinToString(".")

        val check = ReportVerifier(registry(pair)).check(swapped)

        assertThat(check).isInstanceOf(SignatureCheck.Invalid::class.java)
        assertThat((check as SignatureCheck.Invalid).reason).isEqualTo(InvalidReason.SIGNATURE_MISMATCH)
    }

    @Test
    fun `a header swapped after signing does not verify`() {
        // The header is inside the signed bytes precisely so a captured report cannot be
        // re-attributed to another key id.
        val pair = keyPair()
        val json = canonicalReport(emptyList(), "nonce-1")
        val parts = envelope(pair, json).split(".")
        val forgedHeader = envelope(pair, json, keyId = keyIdOf(pair)).split(".")[1]
        val tampered = listOf(parts[0], forgedHeader.dropLast(2) + "AA", parts[2], parts[3]).joinToString(".")

        val check = ReportVerifier(registry(pair)).check(tampered)

        assertThat(check).isInstanceOf(SignatureCheck.Invalid::class.java)
    }

    @Test
    fun `a signature from a different key does not verify`() {
        val enrolled = keyPair()
        val attacker = keyPair()
        // The attacker signs with their own key but claims the enrolled key's id.
        val forged = envelope(attacker, canonicalReport(emptyList(), "nonce-1"), keyId = keyIdOf(enrolled))

        val check = ReportVerifier(registry(enrolled)).check(forged)

        assertThat((check as SignatureCheck.Invalid).reason).isEqualTo(InvalidReason.SIGNATURE_MISMATCH)
    }

    @Test
    fun `an unenrolled key id is invalid rather than accepted`() {
        val check = ReportVerifier(registry(keyPair())).check(envelope(keyPair(), canonicalReport(emptyList(), "n")))
        assertThat((check as SignatureCheck.Invalid).reason).isEqualTo(InvalidReason.UNKNOWN_KEY_ID)
    }

    @Test
    fun `a malformed envelope is rejected without throwing`() {
        val verifier = ReportVerifier(registry(keyPair()))
        listOf("", "nonsense", "IGS1.a.b", "IGS0.a.b.c", "IGS1.!!.b.c", "IGS1.a.b.c.d").forEach {
            assertThat(verifier.check(it)).isInstanceOf(SignatureCheck.Invalid::class.java)
        }
    }

    @Test
    fun `a failed check yields SRV_REPORT_SIGNATURE_INVALID and a passing one yields nothing`() {
        val pair = keyPair()
        val verifier = ReportVerifier(registry(pair))
        val json = canonicalReport(emptyList(), "nonce-1")

        val fromValid = verifier.signalsFrom(verifier.check(envelope(pair, json)))
        val fromUnsigned = verifier.signalsFrom(verifier.check(null))
        val fromInvalid = verifier.signalsFrom(verifier.check(envelope(keyPair(), json, keyIdOf(pair))))

        assertThat(fromValid).isEmpty()
        assertThat(fromUnsigned).isEmpty()
        assertThat(fromInvalid.map { it.id }).containsExactly(SignalId.SRV_REPORT_SIGNATURE_INVALID)
    }

    // --- the two properties that matter --------------------------------------------------

    private fun service(
        verifier: ReportVerifier?,
        policy: Policy = serverPolicy()
    ): Pair<VerificationService, ServerClock> {
        val clock = MutableClock(1_000L)
        return VerificationService(
            challenges = InMemoryChallengeStore(clock),
            scorer = RiskScorer(policy),
            decisionPolicy = DecisionPolicy(),
            clock = clock,
            verifier = verifier
        ) to clock
    }

    private fun findingFor(
        verifier: ReportVerifier?,
        signals: List<Signal>,
        envelope: String?,
        policy: Policy = serverPolicy()
    ): Decision {
        val (svc, _) = service(verifier, policy)
        val challenge = svc.issueChallenge("session-1")
        return svc.verify(
            ReportSubmission(
                sessionId = "session-1",
                report = report(challenge.value, signals),
                envelope = envelope
            )
        )
    }

    @Test
    fun `a valid signature produces exactly the finding an unsigned report produces`() {
        // ADR-0011 §2. If these ever diverge, a good signature has become a route to a better
        // outcome, which is the hole ADR-0007 closed reopened at the transport layer.
        val pair = keyPair()
        val verifier = ReportVerifier(registry(pair))
        val json = canonicalReport(emptyList(), "nonce-1")

        val signed = findingFor(verifier, cleanSignals(), envelope(pair, json))
        val unsigned = findingFor(verifier, cleanSignals(), null)

        assertThat(signed.deviceState).isEqualTo(unsigned.deviceState)
        assertThat(signed.reason).isEqualTo(unsigned.reason)
        assertThat(signed.deviceState).isEqualTo(DeviceState.NO_EVIDENCE_OF_COMPROMISE)
    }

    @Test
    fun `a broken signature does not suppress incriminating evidence`() {
        // The escape hatch this design exists to refuse: if a bad signature discarded the
        // report, a compromised device would corrupt its own signature to shed the accusation.
        val pair = keyPair()
        val verifier = ReportVerifier(registry(pair))
        val forged = envelope(keyPair(), canonicalReport(emptyList(), "nonce-1"), keyIdOf(pair))

        val finding = findingFor(verifier, incriminatingSignals(), forged)

        assertThat(finding.deviceState).isEqualTo(DeviceState.COMPROMISED)
        assertThat(finding.reason).isEqualTo(DecisionReason.SIGNALS_INDICATE_COMPROMISE)
    }

    @Test
    fun `at informational weight an invalid signature changes nothing`() {
        // Hard rule 6: the signal ships at INFORMATIONAL, so it cannot move a finding until a
        // host opts into a weight. A test that skipped this would describe a signal with teeth
        // that the shipped policy does not give it.
        val pair = keyPair()
        val verifier = ReportVerifier(registry(pair))
        val forged = envelope(keyPair(), canonicalReport(emptyList(), "nonce-1"), keyIdOf(pair))

        val finding = findingFor(verifier, cleanSignals(), forged)

        assertThat(finding.deviceState).isEqualTo(DeviceState.NO_EVIDENCE_OF_COMPROMISE)
    }

    @Test
    fun `an opted-in weight lets an invalid signature corroborate, never decide alone`() {
        // POSSIBLE x HIGH is 10 points against a suspicious threshold of 40, so even a host
        // that opts this signal all the way up cannot have it accuse anyone by itself. That
        // is the confidence choice doing its job, not a weakness: key rotation and restored
        // backups land here on honest devices, and every finding is an accusation (ADR-0008).
        val pair = keyPair()
        val verifier = ReportVerifier(registry(pair))
        val forged = envelope(keyPair(), canonicalReport(emptyList(), "nonce-1"), keyIdOf(pair))
        val signatureSignals = verifier.signalsFrom(verifier.check(forged))
        val scorer = RiskScorer(serverPolicy().withWeight(SignalId.SRV_REPORT_SIGNATURE_INVALID, Weight.HIGH))

        val without = scorer.score(lowRiskSignals(), 1.0f)
        val with = scorer.score(lowRiskSignals() + signatureSignals, 1.0f)
        val alone = scorer.score(signatureSignals, 1.0f)

        assertThat(with.riskScore).isGreaterThan(without.riskScore)
        assertThat(alone.verdict).isAnyOf(Verdict.NO_EVIDENCE_OF_COMPROMISE, Verdict.LOW_RISK)
    }

    @Test
    fun `a deployment with no verifier ignores envelopes entirely`() {
        // Failing to check can only fail to incriminate. The opposite default — checking
        // against an empty registry — would accuse every host that has not enrolled yet.
        val finding = findingFor(null, cleanSignals(), "IGS1.garbage.garbage.garbage")
        assertThat(finding.deviceState).isEqualTo(DeviceState.NO_EVIDENCE_OF_COMPROMISE)
    }

    // --- the wire form, end to end --------------------------------------------------------

    @Test
    fun `a signed envelope's payload parses back into a submittable report`() {
        val pair = keyPair()
        val signals = listOf(
            Signal(SignalId.ROOT_SU_BINARY, Category.ROOT, Confidence.CONFIRMED, mapOf("path" to "/system/xbin/su"))
        )
        val json = canonicalReport(signals, "nonce-1")

        val check = ReportVerifier(registry(pair)).check(envelope(pair, json)) as SignatureCheck.Valid
        val parsed = SubmittedReports.fromCanonicalJson(check.canonicalReportJson)!!

        assertThat(parsed.challenge).isEqualTo("nonce-1")
        assertThat(parsed.depth).isEqualTo(Depth.STANDARD)
        assertThat(parsed.signals.map { it.id }).containsExactly(SignalId.ROOT_SU_BINARY)
        assertThat(parsed.signals[0].confidence).isEqualTo(Confidence.CONFIRMED)
    }

    @Test
    fun `an unreadable payload yields no report rather than a guessed one`() {
        assertThat(SubmittedReports.fromCanonicalJson("{}")).isNull()
        assertThat(SubmittedReports.fromCanonicalJson("not json")).isNull()
    }
}
