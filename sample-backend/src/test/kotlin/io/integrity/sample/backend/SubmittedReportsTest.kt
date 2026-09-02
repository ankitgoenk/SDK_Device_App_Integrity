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
import io.integrity.core.Verdict
import io.integrity.core.Weight
import org.junit.Test

/**
 * What an unrecognised label on the wire costs.
 *
 * `category` and `confidence` fell back to `Category.META` and `Confidence.INCONCLUSIVE` — the
 * two values that carry no weight. `META` sidesteps the hooking escalation, which keys on the
 * category rather than the id; `INCONCLUSIVE` has multiplier 0.0 and bypasses every rule keyed
 * on `CONFIRMED`. So the fallbacks were chosen to be maximally harmless, and were therefore
 * exactly what a client wanting a signal neutralised would aim for.
 *
 * The likelier trigger is version skew rather than an attacker — a fleet on an SDK whose
 * `Category` this build predates would have gone silently weightless — and the old behaviour
 * gave neither case anything to see.
 */
class SubmittedReportsTest {

    private val hook = SignalId("HOOK_UNEXPECTED_MODULE")

    private fun wire(id: String, category: String, confidence: String): String {
        val canonical = ReportWire.canonicalJson(
            IntegrityReport(
                verdict = Verdict.NO_EVIDENCE_OF_COMPROMISE,
                riskScore = 0,
                categoryScores = emptyMap(),
                signals = listOf(
                    Signal(SignalId(id), Category.HOOKING, Confidence.CONFIRMED)
                ),
                coverage = 1.0f,
                depth = Depth.STANDARD,
                generatedAtMillis = 0L,
                sdkVersion = "0.1.0-alpha01",
                reportId = "report-1",
                challenge = "nonce-1"
            )
        )
        // Edit the rendered labels rather than building a second serialiser: this is exactly
        // the one-byte, length-preserving change the finding is about.
        return canonical
            .replace(""""category":"HOOKING"""", """"category":"$category"""")
            .replace(""""confidence":"CONFIRMED"""", """"confidence":"$confidence"""")
    }

    private fun scored(report: SubmittedReport): Verdict {
        val policy = Policy.balanced().withWeight(hook, Weight.HIGH)
        return RiskScorer(policy).score(report.signals, coverage = 1.0f).verdict
    }

    @Test
    fun `an honest report escalates on its hooking signal`() {
        // The positive direction. Without it every assertion below passes against a parser
        // that returned nothing useful at all.
        val report = SubmittedReports.fromCanonicalJson(
            wire("HOOK_UNEXPECTED_MODULE", "HOOKING", "CONFIRMED")
        )

        assertThat(report).isNotNull()
        assertThat(scored(report!!)).isEqualTo(Verdict.COMPROMISED)
        assertThat(report.signals.map { it.id }).doesNotContain(SignalId.SRV_REPORT_LABEL_UNRECOGNISED)
    }

    @Test
    fun `a misspelled category cannot take a signal out of the hooking escalation`() {
        // One altered character: capital I to lowercase l. The category is derived from the id
        // now, so the signal keeps its family and the rule still sees it.
        val report = SubmittedReports.fromCanonicalJson(
            wire("HOOK_UNEXPECTED_MODULE", "HOOKlNG", "CONFIRMED")
        )!!

        assertThat(report.signals.first().category).isEqualTo(Category.HOOKING)
        assertThat(scored(report)).isEqualTo(Verdict.COMPROMISED)
    }

    @Test
    fun `a category disagreeing with the id is reported rather than silently corrected`() {
        // Deriving alone would fix the score and lose the telemetry. The catalogue fixes an
        // id's family, so a device sending anything else sent something it could not observe.
        val report = SubmittedReports.fromCanonicalJson(
            wire("HOOK_UNEXPECTED_MODULE", "ROOT", "CONFIRMED")
        )!!

        assertThat(report.signals.map { it.id }).contains(SignalId.SRV_REPORT_LABEL_UNRECOGNISED)
    }

    @Test
    fun `an unrecognised confidence raises a signal instead of scoring zero`() {
        // Confidence has no catalogue authority, so it is still read from the wire and an
        // unreadable one is still INCONCLUSIVE. What changed is that the anomaly is evidence.
        val report = SubmittedReports.fromCanonicalJson(
            wire("HOOK_UNEXPECTED_MODULE", "HOOKING", "CONFIRMEd")
        )!!

        assertThat(report.signals.first().confidence).isEqualTo(Confidence.INCONCLUSIVE)
        val labelSignal = report.signals.single { it.id == SignalId.SRV_REPORT_LABEL_UNRECOGNISED }
        assertThat(labelSignal.confidence).isEqualTo(Confidence.POSSIBLE)
        assertThat(labelSignal.category).isEqualTo(Category.APP_TAMPER)
    }

    @Test
    fun `the label signal can only incriminate`() {
        // ADR-0007 at the parse boundary. It is added to the evidence that arrived, never in
        // place of it, so a report cannot shed a signal by carrying a bad label alongside it.
        val report = SubmittedReports.fromCanonicalJson(
            wire("HOOK_UNEXPECTED_MODULE", "HOOKlNG", "CONFIRMEd")
        )!!

        assertThat(report.signals.map { it.id }).contains(SignalId("HOOK_UNEXPECTED_MODULE"))
        assertThat(report.signals).hasSize(2)
    }

    @Test
    fun `an id in no known family keeps the category it arrived with`() {
        // An integrator feeding their own attestation verdict in is a supported case
        // (DETECTION_TRIAGE.md section 8), and so is an id this build has never heard of.
        val report = SubmittedReports.fromCanonicalJson(
            wire("PARTNER_OWN_CHECK", "ENVIRONMENT", "CONFIRMED")
        )!!

        assertThat(report.signals.first().category).isEqualTo(Category.ENVIRONMENT)
        assertThat(report.signals.map { it.id }).doesNotContain(SignalId.SRV_REPORT_LABEL_UNRECOGNISED)
    }
}
