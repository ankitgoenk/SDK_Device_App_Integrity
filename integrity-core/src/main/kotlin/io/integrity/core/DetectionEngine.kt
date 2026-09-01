package io.integrity.core

import kotlin.time.Duration
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withTimeoutOrNull

/** Raw output of one engine pass, before scoring. */
internal class EngineResult(
    val signals: List<Signal>,
    val coverage: Float,
    /**
     * What each detector did, for [IntegrityDiagnostics]. Never enters the report — see the
     * class doc there for why a list of checks that found nothing must not travel as evidence.
     */
    val runs: List<DetectorRun> = emptyList()
)

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
        val skipped = detectors.filter { it.minDepth.ordinal > depth.ordinal }.map(::skippedRun)
        if (applicable.isEmpty()) {
            return@coroutineScope EngineResult(emptyList(), coverage = 0f, runs = skipped)
        }

        val outcomes = applicable
            .map { detector -> async { runDetector(detector) } }
            .awaitAll()

        val covered = outcomes.count { it.conclusive }
        EngineResult(
            signals = outcomes.flatMap { it.signals },
            coverage = covered.toFloat() / applicable.size,
            runs = applicable.zip(outcomes) { detector, outcome -> outcome.toRun(detector) } + skipped
        )
    }

    private fun skippedRun(detector: Detector) = DetectorRun(
        detectorId = detector.id,
        category = detector.category,
        minDepth = detector.minDepth,
        outcome = RunOutcome.SKIPPED_FOR_DEPTH,
        signalCount = 0,
        durationMillis = NEVER_RAN
    )

    private fun Outcome.toRun(detector: Detector) = DetectorRun(
        detectorId = detector.id,
        category = detector.category,
        minDepth = detector.minDepth,
        outcome = when {
            timedOut -> RunOutcome.TIMED_OUT
            failed -> RunOutcome.FAILED
            signals.isEmpty() -> RunOutcome.FOUND_NOTHING
            signals.any { it.confidence != Confidence.INCONCLUSIVE } -> RunOutcome.EMITTED_EVIDENCE
            else -> RunOutcome.INCONCLUSIVE
        },
        signalCount = signals.size,
        durationMillis = durationMillis
    )

    private suspend fun runDetector(detector: Detector): Outcome {
        val budget = minOf(detector.budget, globalBudget)
        val startedAt = now()
        return try {
            val signals = withTimeoutOrNull(budget) { detector.detect(context) }
                ?: return Outcome(
                    listOf(timedOut(detector)),
                    conclusive = false,
                    timedOut = true,
                    durationMillis = now() - startedAt
                )
            // An empty list means the detector ran and found nothing — that is a real
            // result. Only inconclusive-throughout means it could not determine anything.
            val conclusive = signals.isEmpty() ||
                signals.any { it.confidence != Confidence.INCONCLUSIVE }
            Outcome(signals, conclusive, durationMillis = now() - startedAt)
        } catch (cancellation: CancellationException) {
            throw cancellation
        } catch (failure: Throwable) {
            Outcome(
                listOf(failed(detector, failure)),
                conclusive = false,
                failed = true,
                durationMillis = now() - startedAt
            )
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

    private class Outcome(
        val signals: List<Signal>,
        val conclusive: Boolean,
        val timedOut: Boolean = false,
        val failed: Boolean = false,
        val durationMillis: Long = NEVER_RAN
    )

    private companion object {
        /** Duration for a detector that was never invoked; -1 rather than 0 so it is obvious. */
        const val NEVER_RAN = -1L
    }
}
