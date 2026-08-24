package io.integrity.core

import java.util.UUID

/**
 * The immutable result of one evaluation.
 *
 * [coverage] is reported separately from [riskScore] and answers "is a clean report
 * meaningful?". A TRUSTED verdict at 35% coverage should be treated as UNKNOWN.
 */
public class IntegrityReport(
    public val verdict: Verdict,
    public val riskScore: Int,
    public val categoryScores: Map<Category, Int>,
    public val signals: List<Signal>,
    public val coverage: Float,
    public val depth: Depth,
    public val generatedAtMillis: Long,
    public val sdkVersion: String,
    public val reportId: String,
) {
    public fun hasSignal(id: SignalId): Boolean = signals.any { it.id == id }

    override fun toString(): String =
        "IntegrityReport($verdict, score=$riskScore, coverage=$coverage, signals=${signals.size})"

    public companion object {
        public const val SDK_VERSION: String = "0.1.0-alpha01"

        /** Returned before initialisation, and whenever coverage is too low to judge. */
        public fun unknown(
            depth: Depth,
            signals: List<Signal> = emptyList(),
        ): IntegrityReport = IntegrityReport(
            verdict = Verdict.UNKNOWN,
            riskScore = 0,
            categoryScores = emptyMap(),
            signals = signals,
            coverage = 0f,
            depth = depth,
            generatedAtMillis = System.currentTimeMillis(),
            sdkVersion = SDK_VERSION,
            reportId = UUID.randomUUID().toString(),
        )
    }
}
