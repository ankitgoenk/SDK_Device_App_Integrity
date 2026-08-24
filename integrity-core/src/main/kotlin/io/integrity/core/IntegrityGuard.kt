package io.integrity.core

import android.content.Context
import java.util.concurrent.atomic.AtomicReference

/**
 * SDK entry point.
 *
 * Phase 0 scaffold: configuration and lifecycle are real, the detection engine is not.
 * [evaluate] currently returns an UNKNOWN report carrying
 * [SignalId.META_ENGINE_NOT_IMPLEMENTED]. Phase 1 replaces the body with the real engine
 * (parallel dispatch, per-detector timeouts, crash isolation, caching, scoring) without
 * changing this surface. See docs/PLAN.md.
 */
public object IntegrityGuard {

    private val state = AtomicReference<State?>(null)

    /** Idempotent, non-blocking. Safe to call from Application.onCreate. */
    @JvmStatic
    public fun initialize(context: Context, config: IntegrityConfig) {
        val appContext = context.applicationContext
        state.compareAndSet(null, State(appContext, config))
    }

    @JvmStatic
    public fun isInitialized(): Boolean = state.get() != null

    /** Last cached report, or an UNKNOWN report if none has been produced. Never blocks. */
    @JvmStatic
    public fun currentReport(): IntegrityReport = state.get()?.lastReport?.get() ?: notInitialised(Depth.QUICK)

    /**
     * Runs an evaluation at the requested depth.
     *
     * Safe to call before [initialize]: it returns UNKNOWN rather than throwing.
     */
    public suspend fun evaluate(
        depth: Depth = Depth.STANDARD,
        @Suppress("UNUSED_PARAMETER") force: Boolean = false
    ): IntegrityReport {
        val current = state.get() ?: return notInitialised(depth)

        // TODO(phase-1): replace with DetectionEngine.run(depth) — parallel dispatch,
        //  per-detector budget, crash isolation, cache, then RiskScorer.score(signals).
        val report = IntegrityReport.unknown(
            depth = depth,
            signals = listOf(
                Signal(
                    id = SignalId.META_ENGINE_NOT_IMPLEMENTED,
                    category = Category.META,
                    confidence = Confidence.INCONCLUSIVE,
                    evidence = mapOf("registeredDetectors" to current.config.detectors.size.toString())
                )
            )
        )

        current.lastReport.set(report)
        runCatching { current.config.sink?.onReport(report) }
        return report
    }

    @JvmStatic
    public fun shutdown() {
        state.set(null)
    }

    private fun notInitialised(depth: Depth): IntegrityReport = IntegrityReport.unknown(
        depth = depth,
        signals = listOf(
            Signal(
                id = SignalId.META_CONFIG_INVALID,
                category = Category.META,
                confidence = Confidence.INCONCLUSIVE,
                evidence = mapOf("reason" to "not_initialized")
            )
        )
    )

    private class State(val appContext: Context, val config: IntegrityConfig) {
        val lastReport: AtomicReference<IntegrityReport?> = AtomicReference(null)
    }
}
