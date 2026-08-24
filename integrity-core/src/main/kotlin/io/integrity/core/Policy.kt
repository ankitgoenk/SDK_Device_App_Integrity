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

    public fun withCategoryFactor(category: Category, factor: Double): Policy =
        copy(categoryFactors = categoryFactors + (category to factor.coerceIn(0.0, 1.0)))

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
         * Weights for the signals that exist today. Detector families in phases 2-7 add
         * theirs alongside the detector, per the definition of done in CONTRIBUTING.md.
         * Anything absent scores as INFORMATIONAL.
         */
        private val BASE_WEIGHTS: Map<SignalId, Weight> = mapOf(
            // Removing the native library is the cheapest bypass there is, so its absence
            // must cost something rather than being silently treated as "clean".
            SignalId.META_NATIVE_UNAVAILABLE to Weight.HIGH,
            SignalId.APP_SIGNATURE_MISMATCH to Weight.HIGH,
            SignalId.APP_DEX_DIGEST_MISMATCH to Weight.HIGH,
            SignalId.ATT_APP_NOT_RECOGNISED to Weight.HIGH
        )

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
        public fun observability(): Policy = balanced().copy(advisoryOnly = true)

        /** Banking, wallets, high-value payments: environment signals matter more. */
        @JvmStatic
        public fun strict(): Policy = balanced()
            .copy(
                lowRiskThreshold = 10,
                suspiciousThreshold = 30,
                compromisedThreshold = 65,
                minimumCoverage = 0.7f
            )

        /** Anti-cheat: memory editors and virtualised containers dominate. */
        @JvmStatic
        public fun gaming(): Policy = balanced()
            .withCategoryFactor(Category.EMULATION, 1.0)
            .withCategoryFactor(Category.ENVIRONMENT, 1.0)
    }
}
