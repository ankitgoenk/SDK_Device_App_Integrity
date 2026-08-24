package io.integrity.core

/**
 * How much a signal contributes to its category's subscore.
 *
 * New signals ship [INFORMATIONAL] and are promoted only once shadow-mode data justifies
 * it (docs/RISK_SCORING.md). An unknown signal is therefore scored as INFORMATIONAL:
 * forgetting to assign a weight can never cause a false positive.
 */
public enum class Weight(public val points: Int) {
    HIGH(25),
    MEDIUM(12),
    LOW(5),
    INFORMATIONAL(0)
}

private const val CONFIRMED_MULTIPLIER = 1.0
private const val LIKELY_MULTIPLIER = 0.7
private const val POSSIBLE_MULTIPLIER = 0.4

/**
 * Multiplier applied to a weight, so a hedged observation counts for less.
 *
 * INCONCLUSIVE contributes nothing: a check that could not run is not evidence, and must
 * move coverage rather than the score.
 */
internal val Confidence.multiplier: Double
    get() = when (this) {
        Confidence.CONFIRMED -> CONFIRMED_MULTIPLIER
        Confidence.LIKELY -> LIKELY_MULTIPLIER
        Confidence.POSSIBLE -> POSSIBLE_MULTIPLIER
        Confidence.INCONCLUSIVE -> 0.0
    }
