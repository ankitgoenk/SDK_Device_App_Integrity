package io.integrity.sample.backend

import io.integrity.core.Category
import io.integrity.core.Confidence
import io.integrity.core.Depth
import io.integrity.core.ReportWireParser
import io.integrity.core.Signal
import io.integrity.core.Verdict

/**
 * Builds a [SubmittedReport] from the canonical wire form.
 *
 * The client-side other half is `ReportWire`; the parsing is `ReportWireParser`, in
 * `integrity-model`, so both ends use one implementation of the format. What is left here is
 * only the mapping from "what arrived" to "what this backend holds".
 *
 * **This must be called on bytes whose signature has already been checked**, and on those
 * exact bytes — never on a re-serialisation of something parsed earlier. ADR-0011 §3.
 */
object SubmittedReports {

    /**
     * Returns null on anything that does not map, which the caller turns into
     * `INSUFFICIENT_EVIDENCE`.
     *
     * Rejecting is the safe direction and the only one available: a report this backend
     * cannot read is one whose evidence it cannot score, and the alternative — substituting
     * defaults for the parts it did not understand — would invent a report nobody sent. Note
     * the asymmetry holds even here, because `INSUFFICIENT_EVIDENCE` grants nothing.
     *
     * A consequence worth stating: a future client that adds a [Depth] this build does not
     * know is rejected rather than partially read. That is a deliberate cost of refusing to
     * guess, and the version field exists so the mismatch is diagnosable.
     */
    fun fromCanonicalJson(canonicalJson: String): SubmittedReport? {
        val parsed = ReportWireParser.parse(canonicalJson) ?: return null
        val depth = enumOrNull<Depth>(parsed.depth) ?: return null

        val signals = parsed.signals.map { signal ->
            Signal(
                id = signal.id,
                // An unrecognised category or confidence is mapped to the value that carries
                // no weight rather than rejecting the report. Dropping incriminating evidence
                // because one of its labels was unfamiliar would let a client shed a signal by
                // misspelling its category.
                category = enumOrNull<Category>(signal.category) ?: Category.META,
                confidence = enumOrNull<Confidence>(signal.confidence) ?: Confidence.INCONCLUSIVE,
                evidence = signal.evidence
            )
        }

        return SubmittedReport(
            challenge = parsed.challenge,
            sdkVersion = parsed.sdkVersion,
            depth = depth,
            signals = signals,
            generatedAtMillis = parsed.generatedAtMillis,
            clientAdvisory = parsed.clientAdvisory?.let { advisory ->
                // The advisory is diagnostics that no decision reads (ADR-0006 §2), so an
                // unreadable one is dropped rather than allowed to fail the whole report.
                val verdict = enumOrNull<Verdict>(advisory.verdict) ?: return@let null
                ClientAdvisory(
                    verdict = verdict,
                    riskScore = advisory.riskScore.toInt(),
                    coveragePermille = parsed.coveragePermille.toInt()
                )
            }
        )
    }

    private inline fun <reified T : Enum<T>> enumOrNull(name: String): T? =
        enumValues<T>().firstOrNull { it.name == name }
}
