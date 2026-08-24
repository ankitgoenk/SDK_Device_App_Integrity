package io.integrity.core

import com.google.common.truth.Truth.assertThat
import org.junit.Test

class RiskScorerTest {

    private fun policy() = Policy.balanced()
        .withWeight(ROOT_A, Weight.HIGH)
        .withWeight(ROOT_B, Weight.HIGH)
        .withWeight(HOOK_A, Weight.HIGH)
        .withWeight(ENV_A, Weight.LOW)
        .withWeight(SignalId.APP_SIGNATURE_MISMATCH, Weight.HIGH)
        .withWeight(SignalId.APP_DEX_DIGEST_MISMATCH, Weight.HIGH)
        .withWeight(SignalId.ATT_APP_NOT_RECOGNISED, Weight.HIGH)

    private fun score(signals: List<Signal>, coverage: Float = 1f, policy: Policy = policy()) =
        RiskScorer(policy).score(signals, coverage)

    @Test
    fun `no signals is trusted`() {
        val result = score(emptyList())

        assertThat(result.verdict).isEqualTo(Verdict.TRUSTED)
        assertThat(result.riskScore).isEqualTo(0)
    }

    @Test
    fun `confidence scales a signal's contribution`() {
        val confirmed = score(listOf(Signal(ROOT_A, Category.ROOT, Confidence.CONFIRMED)))
        val likely = score(listOf(Signal(ROOT_A, Category.ROOT, Confidence.LIKELY)))
        val possible = score(listOf(Signal(ROOT_A, Category.ROOT, Confidence.POSSIBLE)))

        assertThat(confirmed.riskScore).isGreaterThan(likely.riskScore)
        assertThat(likely.riskScore).isGreaterThan(possible.riskScore)
    }

    @Test
    fun `inconclusive signals never contribute to the score`() {
        val result = score(listOf(Signal(ROOT_A, Category.ROOT, Confidence.INCONCLUSIVE)))

        assertThat(result.riskScore).isEqualTo(0)
        assertThat(result.verdict).isEqualTo(Verdict.TRUSTED)
    }

    @Test
    fun `a category saturates so correlated signals cannot inflate it`() {
        val many = (1..10).map { Signal(ROOT_A, Category.ROOT, Confidence.CONFIRMED) }

        assertThat(score(many).categoryScores[Category.ROOT]).isEqualTo(100)
    }

    @Test
    fun `two corroborating categories outweigh either alone`() {
        val single = score(
            listOf(
                Signal(ROOT_A, Category.ROOT, Confidence.LIKELY),
                Signal(ROOT_B, Category.ROOT, Confidence.LIKELY)
            )
        )
        val both = score(
            listOf(
                Signal(ROOT_A, Category.ROOT, Confidence.LIKELY),
                Signal(ROOT_B, Category.ROOT, Confidence.LIKELY),
                Signal(ENV_A, Category.ENVIRONMENT, Confidence.CONFIRMED)
            )
        )

        assertThat(both.riskScore).isGreaterThan(single.riskScore)
    }

    @Test
    fun `any confirmed hooking signal is compromised`() {
        val result = score(listOf(Signal(HOOK_A, Category.HOOKING, Confidence.CONFIRMED)))

        assertThat(result.verdict).isEqualTo(Verdict.COMPROMISED)
    }

    @Test
    fun `a merely possible hooking signal does not escalate`() {
        val result = score(listOf(Signal(HOOK_A, Category.HOOKING, Confidence.POSSIBLE)))

        assertThat(result.verdict).isNotEqualTo(Verdict.COMPROMISED)
    }

    @Test
    fun `signature mismatch is decisive on its own`() {
        val result = score(
            listOf(Signal(SignalId.APP_SIGNATURE_MISMATCH, Category.APP_TAMPER, Confidence.CONFIRMED))
        )

        assertThat(result.verdict).isEqualTo(Verdict.COMPROMISED)
    }

    @Test
    fun `dex digest mismatch is decisive on its own`() {
        val result = score(
            listOf(Signal(SignalId.APP_DEX_DIGEST_MISMATCH, Category.APP_TAMPER, Confidence.CONFIRMED))
        )

        assertThat(result.verdict).isEqualTo(Verdict.COMPROMISED)
    }

    @Test
    fun `an unrecognised app per attestation is decisive on its own`() {
        val result = score(
            listOf(Signal(SignalId.ATT_APP_NOT_RECOGNISED, Category.ATTESTATION, Confidence.CONFIRMED))
        )

        assertThat(result.verdict).isEqualTo(Verdict.COMPROMISED)
    }

    @Test
    fun `a promoted missing native library is suspicious with a score floor`() {
        val result = score(
            listOf(Signal(SignalId.META_NATIVE_UNAVAILABLE, Category.META, Confidence.CONFIRMED)),
            policy = Policy.balanced().withWeight(SignalId.META_NATIVE_UNAVAILABLE, Weight.HIGH)
        )

        assertThat(result.verdict).isEqualTo(Verdict.SUSPICIOUS)
        assertThat(result.riskScore).isAtLeast(50)
    }

    @Test
    fun `an unpromoted missing native library cannot move the score through the floor`() {
        // A floor is an escalation wearing a number. Gating escalate() but not the floor
        // left the same bypass open, which is how this slipped through once already.
        val result = score(
            listOf(Signal(SignalId.META_NATIVE_UNAVAILABLE, Category.META, Confidence.CONFIRMED)),
            policy = Policy.balanced()
        )

        assertThat(result.riskScore).isEqualTo(0)
        assertThat(result.verdict).isEqualTo(Verdict.TRUSTED)
    }

    @Test
    fun `the default policy ships no weights at all`() {
        val policy = Policy.balanced()

        assertThat(policy.weightOf(SignalId.META_NATIVE_UNAVAILABLE)).isEqualTo(Weight.INFORMATIONAL)
        assertThat(policy.weightOf(SignalId.APP_SIGNATURE_MISMATCH)).isEqualTo(Weight.INFORMATIONAL)
        assertThat(policy.weightOf(SignalId.ROOT_SU_BINARY)).isEqualTo(Weight.INFORMATIONAL)
    }

    @Test
    fun `low coverage yields unknown rather than trusted`() {
        val result = score(emptyList(), coverage = 0.1f)

        assertThat(result.verdict).isEqualTo(Verdict.UNKNOWN)
    }

    @Test
    fun `low coverage yields unknown even with evidence`() {
        val result = score(
            listOf(Signal(HOOK_A, Category.HOOKING, Confidence.CONFIRMED)),
            coverage = 0.1f
        )

        assertThat(result.verdict).isEqualTo(Verdict.UNKNOWN)
    }

    @Test
    fun `disabled signals are ignored entirely`() {
        val result = score(
            listOf(Signal(HOOK_A, Category.HOOKING, Confidence.CONFIRMED)),
            policy = policy().withDisabled(HOOK_A)
        )

        assertThat(result.verdict).isEqualTo(Verdict.TRUSTED)
        assertThat(result.riskScore).isEqualTo(0)
    }

    @Test
    fun `unweighted signals are informational so a forgotten weight cannot lock anyone out`() {
        val unknown = SignalId("ROOT_SOMETHING_NEW")
        val result = score(listOf(Signal(unknown, Category.ROOT, Confidence.CONFIRMED)))

        assertThat(result.riskScore).isEqualTo(0)
        assertThat(result.verdict).isEqualTo(Verdict.TRUSTED)
    }

    @Test
    fun `observability policy reports risk but never escalates`() {
        val result = score(
            listOf(Signal(HOOK_A, Category.HOOKING, Confidence.CONFIRMED)),
            policy = Policy.observability().withWeight(HOOK_A, Weight.HIGH)
        )

        assertThat(result.riskScore).isGreaterThan(0)
        assertThat(result.verdict).isNotEqualTo(Verdict.COMPROMISED)
    }

    @Test
    fun `thresholds are configurable`() {
        val signals = listOf(Signal(ENV_A, Category.ENVIRONMENT, Confidence.CONFIRMED))
        val lenient = score(signals, policy = policy().withThresholds(lowRisk = 99))
        val harsh = score(signals, policy = policy().withThresholds(lowRisk = 1, suspicious = 2))

        assertThat(lenient.verdict).isEqualTo(Verdict.TRUSTED)
        assertThat(harsh.verdict).isEqualTo(Verdict.SUSPICIOUS)
    }

    @Test
    fun `an escalation cannot fire for a signal still shipping informational`() {
        // Hard rule 6 would be a fiction otherwise: a brand-new signal named by an
        // escalation rule could force COMPROMISED before anyone had seen its FP rate.
        val unpromoted = Policy.balanced()

        val result = score(
            listOf(Signal(SignalId.APP_SIGNATURE_MISMATCH, Category.APP_TAMPER, Confidence.CONFIRMED)),
            policy = unpromoted
        )

        assertThat(result.verdict).isEqualTo(Verdict.TRUSTED)
        assertThat(result.riskScore).isEqualTo(0)
    }

    @Test
    fun `promoting the weight arms the escalation`() {
        val promoted = Policy.balanced().withWeight(SignalId.APP_SIGNATURE_MISMATCH, Weight.HIGH)

        val result = score(
            listOf(Signal(SignalId.APP_SIGNATURE_MISMATCH, Category.APP_TAMPER, Confidence.CONFIRMED)),
            policy = promoted
        )

        assertThat(result.verdict).isEqualTo(Verdict.COMPROMISED)
    }

    @Test
    fun `an unpromoted confirmed hooking signal does not escalate either`() {
        val result = score(
            listOf(Signal(HOOK_A, Category.HOOKING, Confidence.CONFIRMED)),
            policy = Policy.balanced()
        )

        assertThat(result.verdict).isEqualTo(Verdict.TRUSTED)
    }

    @Test
    fun `score never exceeds one hundred`() {
        val everything = Category.entries.map { Signal(ROOT_A, it, Confidence.CONFIRMED) }

        assertThat(score(everything).riskScore).isAtMost(100)
    }
}
