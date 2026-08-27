package io.integrity.core

import java.util.UUID

/**
 * The immutable result of one evaluation.
 *
 * [coverage] is reported separately from [riskScore] and answers "is a clean report
 * meaningful?". A NO_EVIDENCE_OF_COMPROMISE verdict at 35% coverage means almost nothing ran.
 */
// Ten constructor parameters, one over detekt's threshold. Suppressed rather than fixed
// here because the fix worth making is not "fewer parameters": it is grouping verdict,
// riskScore and categoryScores into an advisory holder, so the Kotlin type mirrors the
// clientAdvisory fencing the wire format already has and misuse reads as wrong in Kotlin
// too. That changes the public report type, and bundling it with challenge binding would
// confound two changes in one diff. Tracked in ADR-0006.
@Suppress("LongParameterList")
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
    /**
     * The server-issued nonce this evaluation answered, if any.
     *
     * Carried on the report rather than supplied at serialisation time, deliberately: an
     * API that accepts a challenge when producing the wire form is an API for stamping a
     * fresh nonce onto old evidence. See ADR-0006.
     */
    public val challenge: String? = null
) {
    public fun hasSignal(id: SignalId): Boolean = signals.any { it.id == id }

    override fun toString(): String =
        "IntegrityReport($verdict, score=$riskScore, coverage=$coverage, signals=${signals.size})"

    public companion object {
        public const val SDK_VERSION: String = "0.1.0-alpha01"

        /** Returned before initialisation, and whenever coverage is too low to judge. */
        public fun unknown(depth: Depth, signals: List<Signal> = emptyList()): IntegrityReport = IntegrityReport(
            verdict = Verdict.UNKNOWN,
            riskScore = 0,
            categoryScores = emptyMap(),
            signals = signals,
            coverage = 0f,
            depth = depth,
            generatedAtMillis = System.currentTimeMillis(),
            sdkVersion = SDK_VERSION,
            reportId = UUID.randomUUID().toString(),
            challenge = null
        )
    }
}
