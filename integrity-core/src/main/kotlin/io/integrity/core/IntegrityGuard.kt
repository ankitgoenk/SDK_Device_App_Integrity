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
    public suspend fun evaluate(
        depth: Depth = Depth.STANDARD,
        force: Boolean = false,
        challenge: String? = null
    ): IntegrityReport {
        val current = state.get() ?: return notInitialised(depth)
        val startedAt = System.currentTimeMillis()

        if (mayServeFromCache(force, challenge)) {
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
            reportId = UUID.randomUUID().toString(),
            challenge = challenge
        )

        current.publish(depth, report, startedAt, cacheable = mayCache(challenge))
        // Diagnostics are delivered separately and never travel with the report: a list of
        // checks that found nothing is exactly the shape of thing ADR-0007 forbids as evidence.
        current.publishDiagnostics(depth, report.reportId, result.runs)
        return report
    }

    /**
     * Whether a cached report may answer this call.
     *
     * A challenged evaluation never may. The challenge exists to show the evidence was
     * gathered in response to *this* request; answering it from a sweep that finished
     * minutes ago, with the new nonce stamped on, is replay with extra steps.
     */
    internal fun mayServeFromCache(force: Boolean, challenge: String?): Boolean = !force && challenge == null

    /**
     * Whether the resulting report may enter the cache.
     *
     * The other direction, and easier to miss: a cached challenged report would later be
     * handed to a plain `evaluate()` still carrying someone else's nonce, which the host
     * might forward as though it answered a request the backend never issued.
     */
    internal fun mayCache(challenge: String?): Boolean = challenge == null

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

        fun publish(depth: Depth, report: IntegrityReport, nowMillis: Long, cacheable: Boolean) {
            if (cacheable) cache.put(depth, report, nowMillis)
            lastReport.set(report)
            scope.launch { reports.emit(report) }
            // A sink that throws is the host's bug, and must not become ours.
            runCatching { config.sink?.onReport(report) }
        }

        fun publishDiagnostics(depth: Depth, reportId: String, runs: List<DetectorRun>) {
            val sink = config.diagnosticsSink ?: return
            val diagnostics = IntegrityDiagnostics(
                depth = depth,
                reportId = reportId,
                runs = runs,
                sdkVersion = IntegrityReport.SDK_VERSION
            )
            runCatching { sink.onDiagnostics(diagnostics) }
        }
    }

    private class DefaultDetectionContext(override val appContext: Context, override val config: IntegrityConfig) :
        DetectionContext
}
