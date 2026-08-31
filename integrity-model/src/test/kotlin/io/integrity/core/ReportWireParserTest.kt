package io.integrity.core

import com.google.common.truth.Truth.assertThat
import org.junit.Test

/**
 * The parser's contract is not "reads a report". It is **accepts exactly what [ReportWire]
 * emits, and nothing wider** — because under a signature check every input the parser accepts
 * and the serialiser would never produce is a document whose meaning nothing else audits.
 *
 * So most of what follows asserts rejection.
 */
class ReportWireParserTest {

    private fun report(signals: List<Signal> = emptyList(), challenge: String? = "nonce-1", coverage: Float = 0.83f) =
        IntegrityReport(
            verdict = Verdict.LOW_RISK,
            riskScore = 12,
            categoryScores = mapOf(Category.ROOT to 12),
            signals = signals,
            coverage = coverage,
            depth = Depth.STANDARD,
            generatedAtMillis = 1_700_000_000_000L,
            sdkVersion = "0.1.0-alpha01",
            reportId = "report-1",
            challenge = challenge
        )

    @Test
    fun `round trips a report through the canonical form`() {
        val original = report(
            signals = listOf(
                Signal(
                    id = SignalId.ROOT_SU_BINARY,
                    category = Category.ROOT,
                    confidence = Confidence.LIKELY,
                    evidence = mapOf("path" to "/system/xbin/su")
                )
            )
        )

        val parsed = ReportWireParser.parse(ReportWire.canonicalJson(original))!!

        assertThat(parsed.reportId).isEqualTo("report-1")
        assertThat(parsed.challenge).isEqualTo("nonce-1")
        assertThat(parsed.sdkVersion).isEqualTo("0.1.0-alpha01")
        assertThat(parsed.depth).isEqualTo("STANDARD")
        assertThat(parsed.wireVersion).isEqualTo(ReportWire.WIRE_VERSION.toLong())
        assertThat(parsed.coveragePermille).isEqualTo(830L)
        assertThat(parsed.signals).hasSize(1)
        assertThat(parsed.signals[0].id).isEqualTo(SignalId.ROOT_SU_BINARY)
        assertThat(parsed.signals[0].evidence).containsExactly("path", "/system/xbin/su")
    }

    @Test
    fun `an unbound report round trips with a null challenge`() {
        val parsed = ReportWireParser.parse(ReportWire.canonicalJson(report(challenge = null)))!!
        assertThat(parsed.challenge).isNull()
    }

    @Test
    fun `escaped strings survive the round trip`() {
        val nasty = "quote\" backslash\\ newline\n tab\t control unicodeé"
        val original = report(
            signals = listOf(
                Signal(
                    id = SignalId("ROOT_SU_BINARY"),
                    category = Category.ROOT,
                    confidence = Confidence.POSSIBLE,
                    evidence = mapOf("odd" to nasty)
                )
            )
        )
        val parsed = ReportWireParser.parse(ReportWire.canonicalJson(original))!!
        assertThat(parsed.signals[0].evidence["odd"]).isEqualTo(nasty)
    }

    @Test
    fun `the advisory is parsed but kept boxed away from the top level`() {
        val parsed = ReportWireParser.parse(ReportWire.canonicalJson(report()))!!
        assertThat(parsed.clientAdvisory!!.verdict).isEqualTo("LOW_RISK")
        assertThat(parsed.clientAdvisory!!.riskScore).isEqualTo(12L)
    }

    // --- rejection: everything below is a second spelling of something ------------------

    @Test
    fun `rejects trailing content after the document`() {
        val json = ReportWire.canonicalJson(report())
        assertThat(ReportWireParser.parse("$json{}")).isNull()
        assertThat(ReportWireParser.parse("$json ")).isNull()
    }

    @Test
    fun `rejects insignificant whitespace`() {
        val json = ReportWire.canonicalJson(report())
        assertThat(ReportWireParser.parse(" $json")).isNull()
        assertThat(ReportWireParser.parse(json.replaceFirst("{", "{ "))).isNull()
    }

    @Test
    fun `rejects a duplicated key rather than choosing a winner`() {
        // The classic way two components read one signed document differently.
        val json = """{"a":1,"a":2}"""
        assertThat(JsonReader.read(json)).isNull()
    }

    @Test
    fun `rejects floats and exponents`() {
        // coverage is per mille precisely so no number here is a float.
        assertThat(JsonReader.read("""{"coveragePermille":0.83}""")).isNull()
        assertThat(JsonReader.read("""{"coveragePermille":8.3e2}""")).isNull()
    }

    @Test
    fun `rejects leading zeros and negative zero`() {
        assertThat(JsonReader.read("""{"n":01}""")).isNull()
        assertThat(JsonReader.read("""{"n":-0}""")).isNull()
    }

    @Test
    fun `rejects booleans and escapes the writer never emits`() {
        assertThat(JsonReader.read("""{"n":true}""")).isNull()
        assertThat(JsonReader.read("""{"n":"\/"}""")).isNull()
        assertThat(JsonReader.read("""{"n":"\b"}""")).isNull()
        // Upper-case hex is a second spelling; the writer emits lower case only.
        assertThat(JsonReader.read("""{"n":"\u001F"}""")).isNull()
        assertThat(JsonReader.read("""{"n":"\u001f"}""")).isNotNull()
    }

    @Test
    fun `rejects a raw control character inside a string`() {
        assertThat(JsonReader.read("{\"n\":\"a\u0001b\"}")).isNull()
    }

    @Test
    fun `rejects a coverage outside the per mille range`() {
        val json = ReportWire.canonicalJson(report()).replace("\"coveragePermille\":830", "\"coveragePermille\":1001")
        assertThat(ReportWireParser.parse(json)).isNull()
    }

    @Test
    fun `rejects a missing required field`() {
        val json = ReportWire.canonicalJson(report()).replace("\"reportId\":\"report-1\",", "")
        assertThat(ReportWireParser.parse(json)).isNull()
    }

    @Test
    fun `a malformed advisory drops the advisory without failing the report`() {
        // The advisory is diagnostics no decision reads. Failing the parse on it would let a
        // client shed its own incriminating signals by corrupting the harmless part.
        val original = report(
            signals = listOf(
                Signal(SignalId.ROOT_SU_BINARY, Category.ROOT, Confidence.CONFIRMED)
            )
        )
        val json = ReportWire.canonicalJson(original).replace("\"riskScore\":12", "\"riskScore\":\"12\"")

        val parsed = ReportWireParser.parse(json)!!

        assertThat(parsed.clientAdvisory).isNull()
        assertThat(parsed.signals).hasSize(1)
    }
}
