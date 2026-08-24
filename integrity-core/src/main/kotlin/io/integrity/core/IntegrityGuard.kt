package io.integrity.core

import android.content.Context
import java.util.UUID
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * SDK entry point.
 *
 * Everything here is safe to call before [initialize] and safe to call from any thread:
 * a host that has to reason about ordering will get it wrong, and an integrity SDK that
 * crashes its host is worse than no integrity SDK.
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

    /** Emits every completed evaluation. Cold until [initialize]. */
    public fun reports(): Flow<IntegrityReport> =
        state.get()?.reports?.asSharedFlow() ?: MutableSharedFlow<IntegrityReport>().asSharedFlow()

    /**
     * Runs an evaluation at the requested depth, reusing a cached result when one is still
     * fresh unless [force] is set.
     *
     * Never throws: a detector that fails becomes an INCONCLUSIVE signal, and calling
     * before [initialize] yields UNKNOWN.
     */
    public suspend fun evaluate(depth: Depth = Depth.STANDARD, force: Boolean = false): IntegrityReport {
        val current = state.get() ?: return notInitialised(depth)
        val startedAt = System.currentTimeMillis()

        if (!force) {
            current.cache.get(depth, startedAt)?.let { return it }
        }

        // TODO(phase-9): bound parallelism so the SDK cannot starve the host's dispatcher.
        val result = withContext(Dispatchers.Default) { current.engine.run(depth) }
        val scored = current.scorer.score(result.signals, result.coverage)

        val report = IntegrityReport(
            verdict = scored.verdict,
            riskScore = scored.riskScore,
            categoryScores = scored.categoryScores,
            signals = result.signals,
            coverage = result.coverage,
            depth = depth,
            generatedAtMillis = startedAt,
            sdkVersion = IntegrityReport.SDK_VERSION,
            reportId = UUID.randomUUID().toString()
        )

        current.publish(depth, report, startedAt)
        return report
    }

    @JvmStatic
    public fun shutdown() {
        state.getAndSet(null)?.cache?.clear()
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

    private class State(appContext: Context, val config: IntegrityConfig) {
        val lastReport: AtomicReference<IntegrityReport?> = AtomicReference(null)
        val reports: MutableSharedFlow<IntegrityReport> = MutableSharedFlow(replay = 1)
        val cache: ReportCache = ReportCache(config.cacheTtls)
        val scorer: RiskScorer = RiskScorer(config.policy)
        val engine: DetectionEngine = DetectionEngine(
            detectors = config.detectors,
            context = DefaultDetectionContext(appContext, config),
            globalBudget = config.detectorBudget
        )

        private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

        fun publish(depth: Depth, report: IntegrityReport, nowMillis: Long) {
            cache.put(depth, report, nowMillis)
            lastReport.set(report)
            scope.launch { reports.emit(report) }
            // A sink that throws is the host's bug, and must not become ours.
            runCatching { config.sink?.onReport(report) }
        }
    }

    private class DefaultDetectionContext(override val appContext: Context, override val config: IntegrityConfig) :
        DetectionContext
}
