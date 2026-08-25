package io.integrity.core

import com.google.common.truth.Truth.assertThat
import org.junit.Test

/**
 * Properties of the canonical wire form.
 *
 * A signature over a representation that can render two ways is a signature over nothing,
 * so determinism is the point rather than a nicety. Several of these assert on bytes that
 * *must not* change, which is exactly the kind of test that looks pedantic until a locale
 * or a map implementation changes underneath it.
 */
class ReportWireTest {

    private fun report(
        coverage: Float = 0.83f,
        signals: List<Signal> = emptyList(),
        verdict: Verdict = Verdict.TRUSTED,
        riskScore: Int = 0,
        categoryScores: Map<Category, Int> = emptyMap(),
        challenge: String? = null
    ) = IntegrityReport(
        verdict = verdict,
        riskScore = riskScore,
        categoryScores = categoryScores,
        signals = signals,
        coverage = coverage,
        depth = Depth.FULL,
        generatedAtMillis = 1_735_689_600_000L,
        sdkVersion = "0.1.0-test",
        reportId = "fixed-report-id",
        challenge = challenge
    )

    private fun signal(
        id: SignalId,
        confidence: Confidence = Confidence.POSSIBLE,
        evidence: Map<String, String> = emptyMap()
    ) = Signal(id = id, category = Category.ROOT, confidence = confidence, evidence = evidence)

    /**
     * Top-level keys, found by scanning braces rather than by asking the serialiser.
     *
     * An independent walk, for the same reason the native suite parses its own fixtures with
     * a second implementation: asserting "verdict is not at the top level" against the code
     * that decided where verdict goes would prove only that it is self-consistent.
     */
    private fun topLevelKeys(json: String): List<String> {
        val keys = mutableListOf<String>()
        var index = 0
        var depth = 0

        while (index < json.length) {
            when (json[index]) {
                '"' -> {
                    val (text, next) = readString(json, index)
                    // A key is a string at depth 1 immediately followed by ':'. Nothing else
                    // in valid JSON has that shape, and nested keys sit at depth 2 or more.
                    if (depth == 1 && next < json.length && json[next] == ':') keys.add(text)
                    index = next
                    continue
                }
                '{', '[' -> depth++
                '}', ']' -> depth--
            }
            index++
        }
        return keys
    }

    /** Returns the unescaped contents and the index just past the closing quote. */
    private fun readString(json: String, openQuote: Int): Pair<String, Int> {
        val text = StringBuilder()
        var index = openQuote + 1
        while (index < json.length && json[index] != '"') {
            if (json[index] == '\\') index++
            text.append(json[index])
            index++
        }
        return text.toString() to index + 1
    }

    @Test
    fun theSameReportSerialisesToTheSameBytes() {
        val subject = report(signals = listOf(signal(SignalId.ROOT_SU_BINARY)))

        assertThat(ReportWire.canonicalJson(subject)).isEqualTo(ReportWire.canonicalJson(subject))
    }

    @Test
    fun evidenceKeyOrderDoesNotChangeTheBytes() {
        val forward = signal(SignalId.ROOT_SU_BINARY, evidence = linkedMapOf("a" to "1", "b" to "2"))
        val reversed = signal(SignalId.ROOT_SU_BINARY, evidence = linkedMapOf("b" to "2", "a" to "1"))

        assertThat(ReportWire.canonicalJson(report(signals = listOf(forward))))
            .isEqualTo(ReportWire.canonicalJson(report(signals = listOf(reversed))))
    }

    @Test
    fun detectorRegistrationOrderDoesNotChangeTheBytes() {
        val a = signal(SignalId.ROOT_SU_BINARY)
        val b = signal(SignalId.ROOT_DANGEROUS_PROPS)

        assertThat(ReportWire.canonicalJson(report(signals = listOf(a, b))))
            .isEqualTo(ReportWire.canonicalJson(report(signals = listOf(b, a))))
    }

    /**
     * The single largest canonicalisation hazard: Float.toString is a property of the
     * formatter, not of the value, and 0.83f has no exact binary representation.
     */
    @Test
    fun coverageIsAnIntegerPerMilleAndNeverAFloat() {
        val json = ReportWire.canonicalJson(report(coverage = 0.83f))

        assertThat(json).contains("\"coveragePermille\":830")
        assertThat(json).doesNotContain("0.83")
        assertThat(json).doesNotContain("\"coverage\":")
    }

    @Test
    fun coverageOutsideItsContractIsClampedRatherThanEmitted() {
        assertThat(ReportWire.coveragePermille(Float.NaN)).isEqualTo(0L)
        assertThat(ReportWire.coveragePermille(-1f)).isEqualTo(0L)
        assertThat(ReportWire.coveragePermille(2f)).isEqualTo(1000L)
        assertThat(ReportWire.coveragePermille(1f)).isEqualTo(1000L)
        assertThat(ReportWire.coveragePermille(0f)).isEqualTo(0L)
    }

    /**
     * ADR-0006, and the reason the field moved: a `verdict` beside the evidence invites a
     * reader to treat it as the answer. The backend decides.
     */
    @Test
    fun theClientVerdictIsNotATopLevelField() {
        val json = ReportWire.canonicalJson(report(verdict = Verdict.TRUSTED, riskScore = 17))

        assertThat(topLevelKeys(json)).containsExactly(
            "challenge", "clientAdvisory", "coveragePermille", "depth",
            "generatedAtMillis", "reportId", "sdkVersion", "signals", "wireVersion"
        )
        assertThat(topLevelKeys(json)).doesNotContain("verdict")
        assertThat(topLevelKeys(json)).doesNotContain("riskScore")
        // Still present, just fenced where misuse reads as wrong.
        assertThat(json).contains("\"clientAdvisory\":{")
        assertThat(json).contains("\"verdict\":\"TRUSTED\"")
    }

    /** Hard rule 2, carried across the boundary: "could not check" must reach the backend. */
    @Test
    fun inconclusiveSignalsSurviveSerialisation() {
        val json = ReportWire.canonicalJson(
            report(
                coverage = 0.3f,
                signals = listOf(
                    signal(
                        SignalId.APP_SIGNATURE_MISMATCH,
                        Confidence.INCONCLUSIVE,
                        mapOf("reason" to "no_pin_configured")
                    )
                )
            )
        )

        assertThat(json).contains("\"confidence\":\"INCONCLUSIVE\"")
        assertThat(json).contains("\"reason\":\"no_pin_configured\"")
        assertThat(json).contains("\"coveragePermille\":300")
    }

    @Test
    fun theChallengeIsEchoedAndAbsenceIsExplicit() {
        assertThat(ReportWire.canonicalJson(report(challenge = "nonce-1")))
            .contains("\"challenge\":\"nonce-1\"")
        assertThat(ReportWire.canonicalJson(report(challenge = null)))
            .contains("\"challenge\":null")
    }

    /**
     * The binding is made where the evidence is gathered, or not at all.
     *
     * There is deliberately no way to supply a challenge at serialisation time, so this
     * asserts the consequence: two reports differing only in challenge serialise
     * differently, and no call can make an unchallenged report claim a nonce.
     */
    @Test
    fun aChallengeCannotBeAttachedAfterTheEvidenceWasGathered() {
        val unchallenged = report()
        val challenged = report(challenge = "nonce-1")

        assertThat(ReportWire.canonicalJson(unchallenged)).contains("\"challenge\":null")
        assertThat(ReportWire.canonicalJson(unchallenged))
            .isNotEqualTo(ReportWire.canonicalJson(challenged))
    }

    @Test
    fun stringsWithJsonSyntaxInThemAreEscaped() {
        val json = ReportWire.canonicalJson(
            report(
                signals = listOf(
                    signal(SignalId.ROOT_SU_BINARY, evidence = mapOf("k" to "a\"b\\c\nd\te"))
                )
            )
        )

        assertThat(json).contains("\"a\\\"b\\\\c\\nd\\te\"")
    }

    /**
     * The escape path for control characters, which has now been rewritten twice and was
     * covered by nothing: the named escapes above never exercise it.
     */
    @Test
    fun controlCharactersBecomeFourDigitUnicodeEscapes() {
        val json = ReportWire.canonicalJson(
            report(
                signals = listOf(
                    signal(SignalId.ROOT_SU_BINARY, evidence = mapOf("k" to "\u0001\u001f"))
                )
            )
        )

        assertThat(json).contains("\\u0001\\u001f")
    }

    @Test
    fun categoryScoreOrderDoesNotChangeTheBytes() {
        val forward = linkedMapOf(Category.ROOT to 10, Category.HOOKING to 20)
        val reversed = linkedMapOf(Category.HOOKING to 20, Category.ROOT to 10)

        assertThat(ReportWire.canonicalJson(report(categoryScores = forward)))
            .isEqualTo(ReportWire.canonicalJson(report(categoryScores = reversed)))
    }
}
