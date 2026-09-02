package io.integrity.sample.backend

import io.integrity.core.Category
import io.integrity.core.Confidence
import io.integrity.core.Depth
import io.integrity.core.ReportWireParser
import io.integrity.core.Signal
import io.integrity.core.SignalCategories
import io.integrity.core.SignalId
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
     *
     * **The three fields used to make opposite choices three lines apart.** `depth` refused to
     * guess; `category` and `confidence` guessed, and guessed the value that carries no weight.
     * They are reconciled now, differently for each because they are different kinds of thing:
     * `category` is derived from the id and never read from the wire, `confidence` is still
     * read but an unreadable one raises `SRV_REPORT_LABEL_UNRECOGNISED`, and `depth` still
     * rejects. What none of them does any more is fail silently toward "nothing found".
     */
    fun fromCanonicalJson(canonicalJson: String): SubmittedReport? {
        val parsed = ReportWireParser.parse(canonicalJson) ?: return null
        val depth = enumOrNull<Depth>(parsed.depth) ?: return null

        var unrecognisedLabels = 0

        val signals = parsed.signals.map { signal ->
            // The category is *derived from the id*, not taken from the wire. It is a fact
            // about the id -- `HOOK_UNEXPECTED_MODULE` is always HOOKING -- and `RiskScorer`
            // keys its hooking escalation on it, so leaving it to the client put an
            // attacker-controlled string in front of a rule that forces COMPROMISED.
            val derived = SignalCategories.of(signal.id)
            val declared = enumOrNull<Category>(signal.category)
            // Disagreement between the two is itself worth reporting. Deriving alone would
            // silently *correct* a misspelling, which is right for the score and wrong for
            // telemetry: the catalogue fixes an id's family, so a device sending anything else
            // sent something it could not have observed. Counted whether the declared value
            // failed to parse or parsed to the wrong family.
            if (derived != null && declared != derived) unrecognisedLabels++
            val category = derived ?: declared ?: Category.META.also { unrecognisedLabels++ }

            // Confidence has no such authority -- it is genuinely per-observation -- so it is
            // still read from the wire. What changed is what an unreadable one costs: the
            // INCONCLUSIVE fallback has multiplier 0.0 and bypasses every rule keyed on
            // CONFIRMED, which made it precisely the value a client wanting a signal
            // neutralised would aim for. It is still the safe local default; the anomaly is now
            // reported rather than absorbed.
            val confidence = enumOrNull<Confidence>(signal.confidence)
                ?: Confidence.INCONCLUSIVE.also { unrecognisedLabels++ }

            Signal(
                id = signal.id,
                category = category,
                confidence = confidence,
                evidence = signal.evidence
            )
        }

        // Added to the evidence rather than replacing any of it, and only ever incriminating:
        // ADR-0007's asymmetry at the parse boundary, where unknown input used to fail toward
        // "nothing found". The same shape as `SRV_REPORT_SIGNATURE_INVALID` -- a finding about
        // the report rather than about the device.
        val labelSignal = if (unrecognisedLabels == 0) {
            emptyList()
        } else {
            listOf(
                Signal(
                    id = SignalId.SRV_REPORT_LABEL_UNRECOGNISED,
                    category = Category.APP_TAMPER,
                    confidence = Confidence.POSSIBLE,
                    evidence = mapOf("count" to unrecognisedLabels.toString())
                )
            )
        }

        return SubmittedReport(
            challenge = parsed.challenge,
            sdkVersion = parsed.sdkVersion,
            depth = depth,
            signals = signals + labelSignal,
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
