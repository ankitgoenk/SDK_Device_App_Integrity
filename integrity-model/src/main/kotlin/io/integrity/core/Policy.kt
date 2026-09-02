package io.integrity.core

/**
 * Turns signals into a score. Data, not code: a host can fetch tuned weights from its own
 * config service and apply them at init, so a misbehaving signal is defused without an SDK
 * release. The SDK never fetches anything itself (ADR-0003).
 *
 * See docs/RISK_SCORING.md for the model and the false-positive discipline it encodes.
 */
public class Policy private constructor(
    private val weights: Map<SignalId, Weight>,
    private val disabled: Set<SignalId>,
    private val categoryFactors: Map<Category, Double>,
    public val lowRiskThreshold: Int,
    public val suspiciousThreshold: Int,
    public val compromisedThreshold: Int,
    public val minimumCoverage: Float,
    /** When true, thresholds alone decide the verdict and no escalation rule fires. */
    public val advisoryOnly: Boolean
) {
    public fun weightOf(id: SignalId): Weight = weights[id] ?: Weight.INFORMATIONAL

    public fun isDisabled(id: SignalId): Boolean = id in disabled

    internal fun factorOf(category: Category): Double = categoryFactors[category] ?: 1.0

    public fun withWeight(id: SignalId, weight: Weight): Policy = copy(weights = weights + (id to weight))

    public fun withDisabled(id: SignalId): Policy = copy(disabled = disabled + id)

    /** Per-signal kill switch: a bad detector becomes a config change, not an incident. */
    public fun withDisabled(ids: Collection<SignalId>): Policy = copy(disabled = disabled + ids)

    /**
     * Damps a category's contribution to the combined score. **1.0 is both the maximum and the
     * default, so this can only ever turn a category down.**
     *
     * Stated because the name does not imply it and the clamp is silent:
     * `withCategoryFactor(EMULATION, 2.0)` yields 1.0 and changes nothing. The clamp is not
     * arbitrary — [RiskScorer] combines categories with a noisy-OR, and once `factor * score`
     * exceeds 100 the survival term goes negative and stops being a probability, so
     * monotonicity is lost and more evidence can produce a lower raw score.
     *
     * **To make a signal count for more, weight the signal**, via [withWeight] or the
     * `proposedWeights` helper its detector module ships. That is the per-signal lever, and it
     * is the one `docs/RISK_SCORING.md` was describing when it said categories could be
     * "weighted up" — something this method has never been able to do.
     */
    public fun withCategoryFactor(category: Category, factor: Double): Policy =
        copy(categoryFactors = categoryFactors + (category to factor.coerceIn(0.0, 1.0)))

    /**
     * The coverage below which a report is [Verdict.UNKNOWN] rather than scored.
     *
     * Public because `strict()` differs from `balanced()` partly by raising it, and a host had
     * no way to express that itself: the field was reachable only through the private `copy`.
     */
    public fun withMinimumCoverage(coverage: Float): Policy =
        copy(minimumCoverage = coverage.coerceIn(0f, 1f))

    /** Shadow mode as a modifier rather than only as a named policy. See [observability]. */
    public fun withAdvisoryOnly(advisoryOnly: Boolean): Policy = copy(advisoryOnly = advisoryOnly)

    public fun withThresholds(
        lowRisk: Int = lowRiskThreshold,
        suspicious: Int = suspiciousThreshold,
        compromised: Int = compromisedThreshold
    ): Policy = copy(
        lowRiskThreshold = lowRisk,
        suspiciousThreshold = suspicious,
        compromisedThreshold = compromised
    )

    @Suppress("LongParameterList")
    private fun copy(
        weights: Map<SignalId, Weight> = this.weights,
        disabled: Set<SignalId> = this.disabled,
        categoryFactors: Map<Category, Double> = this.categoryFactors,
        lowRiskThreshold: Int = this.lowRiskThreshold,
        suspiciousThreshold: Int = this.suspiciousThreshold,
        compromisedThreshold: Int = this.compromisedThreshold,
        minimumCoverage: Float = this.minimumCoverage,
        advisoryOnly: Boolean = this.advisoryOnly
    ): Policy = Policy(
        weights = weights,
        disabled = disabled,
        categoryFactors = categoryFactors,
        lowRiskThreshold = lowRiskThreshold,
        suspiciousThreshold = suspiciousThreshold,
        compromisedThreshold = compromisedThreshold,
        minimumCoverage = minimumCoverage,
        advisoryOnly = advisoryOnly
    )

    public companion object {
        /**
         * Deliberately empty.
         *
         * Detector families add their weights alongside the detector, through the
         * `proposedWeights` helper each module ships; anything absent scores as
         * INFORMATIONAL.
         *
         * A weight configured before its producer exists is a landmine: it does nothing
         * until the detector ships, then activates silently. That has now happened twice —
         * APP_SIGNATURE_MISMATCH and META_NATIVE_UNAVAILABLE — so the default policy no
         * longer carries any weight at all, and `tools/check-signal-catalog.py` fails the
         * build if one reappears without a producer.
         *
         * META_NATIVE_UNAVAILABLE in particular must not be weighted until phase 3a has
         * measured how often a .so genuinely fails to load on real devices. Until then it
         * would report the SDK's own robustness problem as a device-integrity finding.
         */
        private val BASE_WEIGHTS: Map<SignalId, Weight> = emptyMap()

        /** Sensible defaults for most apps. */
        @JvmStatic
        public fun balanced(): Policy = Policy(
            weights = BASE_WEIGHTS,
            disabled = emptySet(),
            categoryFactors = emptyMap(),
            lowRiskThreshold = 15,
            suspiciousThreshold = 40,
            compromisedThreshold = 75,
            minimumCoverage = 0.5f,
            advisoryOnly = false
        )

        /**
         * Shadow mode. Every integration should run this for a full release cycle before
         * enforcing anything: the first production release always says something about the
         * user base that the test matrix did not.
         */
        @JvmStatic
        public fun observability(): Policy = balanced().withAdvisoryOnly(true)

        /**
         * Banking, wallets, high-value payments: less score is needed before a verdict moves,
         * and more of the check surface has to have run for the result to count.
         *
         * Thresholds and the coverage floor, and nothing else. `docs/RISK_SCORING.md` used to
         * describe this as promoting `ENV_ACCESSIBILITY_SERVICE` and `ENV_OVERLAY_DETECTED`
         * and treating `UNKNOWN` as risk — none of which it did, and the first two of which
         * are signals no detector emits. Compose `proposedWeights` for weights; `UNKNOWN` is
         * the host's to act on (see the response cookbook), not a policy setting.
         */
        @JvmStatic
        public fun strict(): Policy = balanced()
            .copy(
                lowRiskThreshold = 10,
                suspiciousThreshold = 30,
                compromisedThreshold = 65,
                minimumCoverage = 0.7f
            )

        /**
         * Anti-cheat. **Identical to [balanced] today, and that is the honest state of it.**
         *
         * It used to be `balanced().withCategoryFactor(EMULATION, 1.0)
         * .withCategoryFactor(ENVIRONMENT, 1.0)` — and 1.0 is the default `factorOf` returns,
         * so for every possible input it scored exactly as `balanced` did. Two mistakes
         * stacked: the wrong lever (categories damp, they do not amplify — see
         * [withCategoryFactor]) set to the value that is a no-op.
         *
         * What it is documented to do is weight `ENV_MEMORY_EDITOR`, `EMU_*` and `VIRT_*` up.
         * It cannot: no detector emits any of them (phases 5 and 6), and pre-loading weights
         * for signals with no producer is the landmine [BASE_WEIGHTS] was emptied to remove —
         * inert until the detector ships, then live without anyone deciding.
         *
         * So this stays a named entry point with no distinguishing behaviour yet, rather than
         * a policy that quietly does nothing while claiming otherwise. When the EMU/VIRT
         * detectors land, their weights arrive through `EmulatorDetectors.proposedWeights`
         * alongside them, and this can compose it.
         */
        @JvmStatic
        public fun gaming(): Policy = balanced()
    }
}
