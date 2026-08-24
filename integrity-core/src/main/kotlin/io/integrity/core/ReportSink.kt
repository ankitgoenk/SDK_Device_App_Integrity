package io.integrity.core

import android.util.Log

/**
 * Receives completed reports. The SDK performs no network IO by design (ADR-0003):
 * the host owns transport, pinning, consent and retention.
 *
 * Implementations are called off the main thread, must not throw, and must not block.
 */
public fun interface ReportSink {
    public fun onReport(report: IntegrityReport)
}

/** Development helper. Never enabled by default; logs nothing in release builds. */
public class LogcatSink(private val tag: String = "IntegrityGuard") : ReportSink {
    override fun onReport(report: IntegrityReport) {
        Log.d(tag, report.toString())
    }
}

/** Fans a report out to several sinks, isolating failures in each. */
public class CompositeSink(private val sinks: List<ReportSink>) : ReportSink {
    override fun onReport(report: IntegrityReport) {
        sinks.forEach { sink ->
            runCatching { sink.onReport(report) }
        }
    }
}
