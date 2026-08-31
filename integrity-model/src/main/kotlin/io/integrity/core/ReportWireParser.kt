package io.integrity.core

/**
 * Reads the canonical wire form back into evidence. The other half of [ReportWire].
 *
 * Lives in `integrity-model` so the backend parses with the same code the client serialised
 * with, for the reason that module exists at all: two implementations of one format are two
 * things that must agree, and a security decision is a bad place to find out they do not.
 *
 * ### This does not produce an [IntegrityReport], and that is deliberate
 *
 * It produces a [ParsedReport], which has no `verdict` and no `riskScore` at the top level —
 * they stay boxed in [ParsedAdvisory] exactly as ADR-0006 §2 boxed them on the wire. Parsing
 * into `IntegrityReport` would hand the backend a type with `verdict` sitting at the top,
 * which is the shape the wire format was changed to avoid. The parser is the boundary where
 * that fencing would quietly be undone, so it is the boundary that keeps it.
 *
 * `coverage` is likewise left as an integer per mille and never widened back to a float.
 * ADR-0007 settled that the server has no honest use for it at all; keeping the client's
 * units makes it a claim being reported rather than a number being adopted.
 */
public object ReportWireParser {

    /** What the client said about its own conclusion. Diagnostics only — see ADR-0006 §2. */
    public class ParsedAdvisory(
        public val verdict: String,
        public val riskScore: Long,
        public val categoryScores: Map<String, Long>
    )

    /**
     * A report as it arrived, parsed but not believed.
     *
     * [verdict] and the enums are kept as **strings**, not resolved to [Verdict], [Depth] or
     * [Category]. An unrecognised value is a fact about the submission — an older client, or
     * a probe — and mapping it into an enum would force a choice between throwing and
     * silently substituting a default. Both are worse than reporting what arrived. Only
     * [signals] resolve, because [SignalId] is an open value class over a string and so
     * cannot fail to represent one.
     */
    @Suppress("LongParameterList")
    public class ParsedReport(
        public val wireVersion: Long,
        public val reportId: String,
        public val challenge: String?,
        public val sdkVersion: String,
        public val depth: String,
        public val coveragePermille: Long,
        public val generatedAtMillis: Long,
        public val signals: List<ParsedSignal>,
        public val clientAdvisory: ParsedAdvisory?
    )

    /** One observation as it arrived. */
    public class ParsedSignal(
        public val id: SignalId,
        public val category: String,
        public val confidence: String,
        public val evidence: Map<String, String>
    )

    /**
     * Parses canonical JSON, or returns null.
     *
     * Never throws. A malformed report is an ordinary event on an untrusted boundary, and a
     * caller that has to wrap this in a try/catch will eventually catch too much.
     *
     * **Callers must verify the signature over the received bytes before calling this**, not
     * after and not over anything re-serialised from the result. ADR-0011 §3.
     */
    @Suppress("ReturnCount")
    public fun parse(canonicalJson: String): ParsedReport? {
        val root = JsonReader.read(canonicalJson) as? JsonValue.Obj ?: return null
        val fields = root.fields

        val signalsArray = fields["signals"] as? JsonValue.Arr ?: return null
        val signals = ArrayList<ParsedSignal>(signalsArray.items.size)
        for (item in signalsArray.items) {
            signals.add(parseSignal(item) ?: return null)
        }

        return ParsedReport(
            wireVersion = num(fields["wireVersion"]) ?: return null,
            reportId = str(fields["reportId"]) ?: return null,
            // Null is a legal, meaningful value: an unbound report. Distinguished from
            // absent, which is malformed.
            challenge = when (val challenge = fields["challenge"]) {
                is JsonValue.Str -> challenge.value
                is JsonValue.Null -> null
                else -> return null
            },
            sdkVersion = str(fields["sdkVersion"]) ?: return null,
            depth = str(fields["depth"]) ?: return null,
            coveragePermille = num(fields["coveragePermille"])?.takeIf { it in 0..PER_MILLE } ?: return null,
            generatedAtMillis = num(fields["generatedAtMillis"]) ?: return null,
            signals = signals,
            clientAdvisory = parseAdvisory(fields["clientAdvisory"])
        )
    }

    @Suppress("ReturnCount")
    private fun parseSignal(value: JsonValue): ParsedSignal? {
        val fields = (value as? JsonValue.Obj)?.fields ?: return null
        val evidenceFields = (fields["evidence"] as? JsonValue.Obj)?.fields ?: return null
        val evidence = LinkedHashMap<String, String>(evidenceFields.size)
        for ((key, item) in evidenceFields) {
            evidence[key] = str(item) ?: return null
        }
        return ParsedSignal(
            id = SignalId(str(fields["id"]) ?: return null),
            category = str(fields["category"]) ?: return null,
            confidence = str(fields["confidence"]) ?: return null,
            evidence = evidence
        )
    }

    /**
     * Returns null when the advisory is absent *or* malformed, rather than failing the parse.
     *
     * Every field in it is diagnostics that no decision may read (ADR-0006 §2), so a garbled
     * advisory must not be able to reject a report whose evidence is intact. Rejecting here
     * would let a client discard its own incriminating signals by corrupting the one part of
     * the document that is guaranteed not to matter.
     */
    @Suppress("ReturnCount")
    private fun parseAdvisory(value: JsonValue?): ParsedAdvisory? {
        val fields = (value as? JsonValue.Obj)?.fields ?: return null
        val scoreFields = (fields["categoryScores"] as? JsonValue.Obj)?.fields ?: return null
        val categoryScores = LinkedHashMap<String, Long>(scoreFields.size)
        for ((key, item) in scoreFields) {
            categoryScores[key] = num(item) ?: return null
        }
        return ParsedAdvisory(
            verdict = str(fields["verdict"]) ?: return null,
            riskScore = num(fields["riskScore"]) ?: return null,
            categoryScores = categoryScores
        )
    }

    private fun str(value: JsonValue?): String? = (value as? JsonValue.Str)?.value

    private fun num(value: JsonValue?): Long? = (value as? JsonValue.Num)?.value

    private const val PER_MILLE = 1000L
}
