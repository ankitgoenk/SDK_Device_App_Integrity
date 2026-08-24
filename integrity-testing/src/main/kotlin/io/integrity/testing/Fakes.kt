package io.integrity.testing

import io.integrity.core.Category
import io.integrity.core.Confidence
import io.integrity.core.Depth
import io.integrity.core.DetectionContext
import io.integrity.core.Detector
import io.integrity.core.IntegrityReport
import io.integrity.core.ReportSink
import io.integrity.core.Signal
import io.integrity.core.SignalId
import kotlin.time.Duration
import kotlinx.coroutines.delay

/**
 * A detector whose behaviour is dictated by the test: emit fixed signals, stall past its
 * budget, or throw. Used to exercise the engine's timeout and crash isolation.
 */
public class ScriptedDetector(
    override val id: String = "scripted",
    override val category: Category = Category.META,
    override val minDepth: Depth = Depth.QUICK,
    override val budget: Duration = Detector.DEFAULT_BUDGET,
    private val signals: List<Signal> = emptyList(),
    private val stallFor: Duration? = null,
    private val throwing: Throwable? = null
) : Detector {

    public var invocations: Int = 0
        private set

    override suspend fun detect(context: DetectionContext): List<Signal> {
        invocations++
        throwing?.let { throw it }
        stallFor?.let { delay(it) }
        return signals
    }
}

/** Collects reports for assertions. */
public class InMemorySink : ReportSink {
    private val collected = mutableListOf<IntegrityReport>()

    public val reports: List<IntegrityReport> get() = synchronized(collected) { collected.toList() }

    public val last: IntegrityReport? get() = reports.lastOrNull()

    override fun onReport(report: IntegrityReport) {
        synchronized(collected) { collected += report }
    }
}

/** Convenience factory so tests do not repeat the boilerplate. */
public fun signal(
    id: SignalId,
    category: Category = Category.META,
    confidence: Confidence = Confidence.CONFIRMED,
    evidence: Map<String, String> = emptyMap()
): Signal = Signal(id = id, category = category, confidence = confidence, evidence = evidence)
