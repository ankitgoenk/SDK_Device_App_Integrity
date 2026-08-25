package io.integrity.core

import kotlin.math.min
import kotlin.math.roundToInt

/** The scored view of one evaluation, before it is wrapped in an [IntegrityReport]. */
/**
 * The outcome of scoring a set of signals under a policy.
 *
 * Public because the backend re-scores with this same class rather than trusting the
 * client's numbers (ADR-0006). It was `internal` while the only caller lived in the same
 * module; the extraction is what made a second, drifting implementation the alternative.
 */
public class ScoringResult(
    public val verdict: Verdict,
    public val riskScore: Int,
    public val categoryScores: Map<Category, Int>
)

/**
 * Signals -> category subscores -> one risk score -> a verdict.
 *
 * Categories are combined with a noisy-OR rather than an average: evidence in one category
 * must not be diluted by the categories that found nothing. One category at 100 yields 100;
 * two independent categories at 40 yield 64, which is what makes "two corroborating
 * categories beat any single heuristic" fall out of the arithmetic instead of needing a
 * special case.
 *
 * Escalation rules then apply floors, because some observations are decisive regardless of
 * the arithmetic. See docs/RISK_SCORING.md.
 */
public class RiskScorer(private val policy: Policy) {

    public fun score(signals: List<Signal>, coverage: Float): ScoringResult {
        val active = signals.filterNot { policy.isDisabled(it.id) }
        val categoryScores = categoryScores(active)
        val combined = combine(categoryScores)

        if (coverage < policy.minimumCoverage) {
            // Too little evidence for "clean" to mean anything. Never TRUSTED by default.
            return ScoringResult(Verdict.UNKNOWN, combined, categoryScores)
        }

        val base = verdictFor(combined)
        if (policy.advisoryOnly) {
            return ScoringResult(base, combined, categoryScores)
        }

        // One choke point rather than a check inside each rule. Gating rule-by-rule was
        // tried and forgotten three times — for the decisive signals, then the score
        // floor, then the native-unavailable escalation. Filtering once means a rule
        // added later cannot reintroduce the bypass by omission.
        val actionable = active.filter { policy.weightOf(it.id) != Weight.INFORMATIONAL }
        val escalated = escalate(base, actionable, categoryScores)
        val floor = scoreFloor(actionable)
        return ScoringResult(escalated, maxOf(combined, floor), categoryScores)
    }

    private fun categoryScores(signals: List<Signal>): Map<Category, Int> = signals
        .groupBy { it.category }
        .mapValues { (_, group) ->
            val raw = group.sumOf { policy.weightOf(it.id).points * it.confidence.multiplier }
            min(MAX_SCORE.toDouble(), raw).roundToInt()
        }
        .filterValues { it > 0 }

    /** Noisy-OR across categories, each damped by its policy factor. */
    private fun combine(categoryScores: Map<Category, Int>): Int {
        if (categoryScores.isEmpty()) return 0
        var survives = 1.0
        categoryScores.forEach { (category, score) ->
            survives *= 1.0 - (policy.factorOf(category) * score / MAX_SCORE.toDouble())
        }
        return ((1.0 - survives) * MAX_SCORE).roundToInt().coerceIn(0, MAX_SCORE)
    }

    private fun verdictFor(score: Int): Verdict = when {
        score >= policy.compromisedThreshold -> Verdict.COMPROMISED
        score >= policy.suspiciousThreshold -> Verdict.SUSPICIOUS
        score >= policy.lowRiskThreshold -> Verdict.LOW_RISK
        else -> Verdict.TRUSTED
    }

    private fun escalate(base: Verdict, signals: List<Signal>, categoryScores: Map<Category, Int>): Verdict {
        var verdict = base

        // Callers pass only promoted signals; see the filter in score().
        // Anything confirmed in the hooking family means the process is already owned.
        val confirmedHooking = signals.any {
            it.category == Category.HOOKING && it.confidence == Confidence.CONFIRMED
        }
        if (confirmedHooking) verdict = verdict.atLeast(Verdict.COMPROMISED)

        val decisive = signals.any {
            it.confidence == Confidence.CONFIRMED && it.id in DECISIVE_SIGNALS
        }
        if (decisive) verdict = verdict.atLeast(Verdict.COMPROMISED)

        if (signals.any { it.id == SignalId.META_NATIVE_UNAVAILABLE }) {
            verdict = verdict.atLeast(Verdict.SUSPICIOUS)
        }

        // Corroboration across independent categories beats any single heuristic.
        val corroborating = categoryScores.values.count { it >= policy.suspiciousThreshold }
        if (corroborating >= CORROBORATION_THRESHOLD) verdict = verdict.atLeast(Verdict.SUSPICIOUS)

        return verdict
    }

    // Gated on promotion for the same reason escalations are: a floor is just an
    // escalation wearing a number, and an unpromoted signal must not be able to move the
    // score by any route. The previous fix covered escalate() and missed this one.
    private fun scoreFloor(signals: List<Signal>): Int =
        if (signals.any { it.id == SignalId.META_NATIVE_UNAVAILABLE }) NATIVE_MISSING_FLOOR else 0

    /** UNKNOWN is not on the severity ladder; it is decided by coverage, never raised into. */
    private fun Verdict.atLeast(other: Verdict): Verdict = if (severity(this) >= severity(other)) this else other

    private fun severity(verdict: Verdict): Int = SEVERITY_LADDER.indexOf(verdict)

    private companion object {
        const val MAX_SCORE = 100
        const val NATIVE_MISSING_FLOOR = 50
        const val CORROBORATION_THRESHOLD = 2

        /** Ascending severity. UNKNOWN sits at the bottom: it is decided by coverage. */
        val SEVERITY_LADDER = listOf(
            Verdict.UNKNOWN,
            Verdict.TRUSTED,
            Verdict.LOW_RISK,
            Verdict.SUSPICIOUS,
            Verdict.COMPROMISED
        )

        val DECISIVE_SIGNALS = setOf(
            SignalId.APP_SIGNATURE_MISMATCH,
            SignalId.APP_DEX_DIGEST_MISMATCH,
            SignalId.ATT_APP_NOT_RECOGNISED
        )
    }
}
