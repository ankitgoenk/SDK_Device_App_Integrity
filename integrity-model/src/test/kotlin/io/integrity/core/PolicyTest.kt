package io.integrity.core

import com.google.common.truth.Truth.assertThat
import org.junit.Test

/**
 * One assertion per built-in policy, against the property its documentation claims.
 *
 * `Policy.gaming()` was `balanced().withCategoryFactor(EMULATION, 1.0)
 * .withCategoryFactor(ENVIRONMENT, 1.0)`. 1.0 is the value `factorOf` already returns for an
 * unset category, so for every possible input it scored exactly as `balanced` did — while
 * `docs/RISK_SCORING.md` described it as weighting `ENV_MEMORY_EDITOR`, `EMU_*` and `VIRT_*` up.
 * Nothing compared the prose to the behaviour, and the two mistakes stacked: the wrong lever
 * (category factors damp; they cannot amplify) set to the value that changes nothing.
 *
 * This is the right tool for that rather than another `tools/check-*.py`: a gate comparing prose
 * to behaviour would be brittle, and three lines of Kotlin are not.
 */
class PolicyTest {

    private val root = SignalId("ROOT_SU_BINARY")

    private fun signal(id: SignalId, category: Category, confidence: Confidence) =
        Signal(id = id, category = category, confidence = confidence)

    private fun scoreUnder(policy: Policy, coverage: Float = 1.0f) =
        RiskScorer(policy).score(listOf(signal(root, Category.ROOT, Confidence.CONFIRMED)), coverage)

    // --- thresholds -----------------------------------------------------------------------

    @Test
    fun `strict moves a verdict on less score than balanced`() {
        val weighted = { p: Policy -> p.withWeight(root, Weight.MEDIUM) }

        // MEDIUM (12) x CONFIRMED (1.0) = 12. Balanced's low-risk floor is 15, strict's is 10.
        assertThat(scoreUnder(weighted(Policy.balanced())).verdict)
            .isEqualTo(Verdict.NO_EVIDENCE_OF_COMPROMISE)
        assertThat(scoreUnder(weighted(Policy.strict())).verdict).isEqualTo(Verdict.LOW_RISK)
    }

    @Test
    fun `strict demands more coverage before a report is scored at all`() {
        val weighted = { p: Policy -> p.withWeight(root, Weight.HIGH) }

        // Balanced's floor is 0.5 and strict's is 0.7, so 0.6 is scored by one and not the other.
        assertThat(scoreUnder(weighted(Policy.balanced()), coverage = 0.6f).verdict)
            .isNotEqualTo(Verdict.UNKNOWN)
        assertThat(scoreUnder(weighted(Policy.strict()), coverage = 0.6f).verdict)
            .isEqualTo(Verdict.UNKNOWN)
    }

    // --- advisory mode --------------------------------------------------------------------

    @Test
    fun `observability suppresses escalation and balanced does not`() {
        val hooking = listOf(signal(SignalId("HOOK_TRACER_PID"), Category.HOOKING, Confidence.CONFIRMED))
        val weighted = { p: Policy -> p.withWeight(SignalId("HOOK_TRACER_PID"), Weight.LOW) }

        // LOW (5) alone scores below every threshold; the hooking escalation is what moves it.
        assertThat(RiskScorer(weighted(Policy.balanced())).score(hooking, 1.0f).verdict)
            .isEqualTo(Verdict.COMPROMISED)
        assertThat(RiskScorer(weighted(Policy.observability())).score(hooking, 1.0f).verdict)
            .isEqualTo(Verdict.NO_EVIDENCE_OF_COMPROMISE)
    }

    // --- the no-op ------------------------------------------------------------------------

    @Test
    fun `gaming is balanced today, and says so`() {
        // Pinning the current truth rather than the documentation's aspiration. When the EMU
        // and VIRT detectors ship and `gaming()` composes their proposed weights, this test
        // fails — which is the moment to update the KDoc that currently explains why it does
        // not differ, rather than discovering the divergence from a support ticket.
        val signals = listOf(
            signal(root, Category.ROOT, Confidence.CONFIRMED),
            signal(SignalId("EMU_BUILD_FINGERPRINT"), Category.EMULATION, Confidence.CONFIRMED),
            signal(SignalId("ENV_MEMORY_EDITOR"), Category.ENVIRONMENT, Confidence.CONFIRMED)
        )
        val weight = { p: Policy ->
            p.withWeight(root, Weight.HIGH)
                .withWeight(SignalId("EMU_BUILD_FINGERPRINT"), Weight.HIGH)
                .withWeight(SignalId("ENV_MEMORY_EDITOR"), Weight.HIGH)
        }

        val balanced = RiskScorer(weight(Policy.balanced())).score(signals, 1.0f)
        val gaming = RiskScorer(weight(Policy.gaming())).score(signals, 1.0f)

        assertThat(gaming.riskScore).isEqualTo(balanced.riskScore)
        assertThat(gaming.verdict).isEqualTo(balanced.verdict)
    }

    // --- the lever the documentation described, which does not exist ------------------------

    @Test
    fun `a category factor above one is clamped and changes nothing`() {
        // `docs/RISK_SCORING.md` promised `EMU_*` and `VIRT_*` "weighted up" through this
        // method. It damps only: 1.0 is the maximum and the default, so asking for more is
        // silently the same as asking for nothing. Upweighting is per signal, via withWeight.
        val weighted = Policy.balanced().withWeight(root, Weight.HIGH)

        assertThat(scoreUnder(weighted.withCategoryFactor(Category.ROOT, 2.0)).riskScore)
            .isEqualTo(scoreUnder(weighted).riskScore)
    }

    @Test
    fun `a category factor below one damps its contribution`() {
        // The positive control for the test above: without it, that assertion also passes
        // against a `withCategoryFactor` that ignored its argument entirely.
        val weighted = Policy.balanced().withWeight(root, Weight.HIGH)

        assertThat(scoreUnder(weighted.withCategoryFactor(Category.ROOT, 0.5)).riskScore)
            .isLessThan(scoreUnder(weighted).riskScore)
    }

    // --- the fields that had no public setter ------------------------------------------------

    @Test
    fun `minimum coverage and advisory mode are reachable without the private copy`() {
        assertThat(Policy.balanced().withMinimumCoverage(0.9f).minimumCoverage).isEqualTo(0.9f)
        assertThat(Policy.balanced().withAdvisoryOnly(true).advisoryOnly).isTrue()
        // Coerced rather than trusted: coverage is a fraction by contract.
        assertThat(Policy.balanced().withMinimumCoverage(5f).minimumCoverage).isEqualTo(1f)
    }
}
