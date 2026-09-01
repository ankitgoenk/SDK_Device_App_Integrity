package io.integrity.sample

import io.integrity.core.DetectorRun
import io.integrity.core.IntegrityDiagnostics
import io.integrity.core.RunOutcome
import java.util.concurrent.atomic.AtomicReference

/**
 * Holds the most recent [IntegrityDiagnostics] so the UI can show what ran.
 *
 * Deliberately a plain holder in the sample app rather than anything in the SDK: diagnostics
 * are for a person reading a screen or a tester pasting a bug report, and giving them a
 * persistence story would invite treating them as data.
 */
object DiagnosticsStore {

    private val latest = AtomicReference<IntegrityDiagnostics?>(null)

    fun record(diagnostics: IntegrityDiagnostics) = latest.set(diagnostics)

    fun latest(): IntegrityDiagnostics? = latest.get()

    /**
     * A plain-text account suitable for pasting into an issue.
     *
     * The header is not decoration. Anyone reading a list of checks that found nothing will
     * reach for the conclusion that the device is clean, and the whole design rests on that
     * conclusion being unavailable — so the text says so before it says anything else.
     */
    fun shareText(diagnostics: IntegrityDiagnostics, deviceLine: String): String = buildString {
        appendLine("Integrity SDK ${diagnostics.sdkVersion} — detector run")
        appendLine("Depth: ${diagnostics.depth}   Report: ${diagnostics.reportId}")
        appendLine("Device: $deviceLine")
        appendLine()
        appendLine("NOTE: \"found nothing\" means this check saw no evidence. It is NOT a")
        appendLine("statement that the device is clean — a compromise that hides successfully")
        appendLine("produces exactly the same result. Only the findings below are evidence.")
        appendLine()

        val grouped = diagnostics.runs.groupBy { it.outcome }
        ORDER.forEach { outcome ->
            val runs = grouped[outcome].orEmpty().sortedBy { it.detectorId }
            if (runs.isEmpty()) return@forEach
            appendLine("${label(outcome)} (${runs.size})")
            runs.forEach { appendLine("    ${line(it)}") }
            appendLine()
        }
        appendLine("Total detectors registered: ${diagnostics.runs.size}")
    }

    private fun line(run: DetectorRun): String {
        val timing = if (run.durationMillis < 0) "not run" else "${run.durationMillis}ms"
        val signals = if (run.signalCount == 0) "" else ", ${run.signalCount} signal(s)"
        return "${run.detectorId}  [${run.category}, min ${run.minDepth}]  $timing$signals"
    }

    private fun label(outcome: RunOutcome) = when (outcome) {
        RunOutcome.EMITTED_EVIDENCE -> "FOUND EVIDENCE"
        RunOutcome.INCONCLUSIVE -> "COULD NOT DETERMINE"
        RunOutcome.TIMED_OUT -> "TIMED OUT"
        RunOutcome.FAILED -> "FAILED"
        RunOutcome.FOUND_NOTHING -> "RAN, FOUND NOTHING (not a clean result)"
        RunOutcome.SKIPPED_FOR_DEPTH -> "NOT RUN AT THIS DEPTH"
    }

    /** Findings first, then the states that need reading, then the uninformative bulk. */
    private val ORDER = listOf(
        RunOutcome.EMITTED_EVIDENCE,
        RunOutcome.INCONCLUSIVE,
        RunOutcome.TIMED_OUT,
        RunOutcome.FAILED,
        RunOutcome.FOUND_NOTHING,
        RunOutcome.SKIPPED_FOR_DEPTH
    )
}
