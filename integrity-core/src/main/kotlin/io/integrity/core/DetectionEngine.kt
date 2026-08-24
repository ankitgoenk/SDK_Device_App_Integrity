package io.integrity.core

import kotlin.time.Duration
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withTimeoutOrNull

/** Raw output of one engine pass, before scoring. */
internal class EngineResult(val signals: List<Signal>, val coverage: Float)

/**
 * Runs the applicable detectors in parallel under a per-detector time budget.
 *
 * Two invariants matter more than throughput:
 *  - a detector that throws or overruns must never reach the host, and must never be
 *    mistaken for "found nothing"; it degrades to an INCONCLUSIVE meta signal;
 *  - coverage is reported honestly, so a clean report with poor coverage can be treated
 *    as UNKNOWN rather than as evidence of a healthy device.
 */
internal class DetectionEngine(
    private val detectors: List<Detector>,
    private val context: DetectionContext,
    private val globalBudget: Duration,
    private val now: () -> Long = System::currentTimeMillis
) {

    suspend fun run(depth: Depth): EngineResult = coroutineScope {
        val applicable = detectors.filter { it.minDepth.ordinal <= depth.ordinal }
        if (applicable.isEmpty()) {
            return@coroutineScope EngineResult(emptyList(), coverage = 0f)
        }

        val outcomes = applicable
            .map { detector -> async { runDetector(detector) } }
            .awaitAll()

        val covered = outcomes.count { it.conclusive }
        EngineResult(
            signals = outcomes.flatMap { it.signals },
            coverage = covered.toFloat() / applicable.size
        )
    }

    private suspend fun runDetector(detector: Detector): Outcome {
        val budget = minOf(detector.budget, globalBudget)
        return try {
            val signals = withTimeoutOrNull(budget) { detector.detect(context) }
                ?: return Outcome(listOf(timedOut(detector)), conclusive = false)
            // An empty list means the detector ran and found nothing — that is a real
            // result. Only inconclusive-throughout means it could not determine anything.
            val conclusive = signals.isEmpty() ||
                signals.any { it.confidence != Confidence.INCONCLUSIVE }
            Outcome(signals, conclusive)
        } catch (cancellation: CancellationException) {
            throw cancellation
        } catch (failure: Throwable) {
            Outcome(listOf(failed(detector, failure)), conclusive = false)
        }
    }

    private fun timedOut(detector: Detector) = Signal(
        id = SignalId.META_DETECTOR_TIMEOUT,
        category = Category.META,
        confidence = Confidence.INCONCLUSIVE,
        evidence = mapOf("detector" to detector.id, "budgetMs" to detector.budget.inWholeMilliseconds.toString()),
        detectedAtMillis = now()
    )

    // Only the exception's class name: a message can carry paths or user data.
    private fun failed(detector: Detector, failure: Throwable) = Signal(
        id = SignalId.META_DETECTOR_ERROR,
        category = Category.META,
        confidence = Confidence.INCONCLUSIVE,
        evidence = mapOf("detector" to detector.id, "exception" to (failure::class.simpleName ?: "unknown")),
        detectedAtMillis = now()
    )

    private class Outcome(val signals: List<Signal>, val conclusive: Boolean)
}
