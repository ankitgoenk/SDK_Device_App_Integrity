package io.integrity.core

import android.content.Context
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds

/**
 * A single detection unit.
 *
 * Contract:
 * - never touch the main thread, never block indefinitely, honour cancellation;
 * - when a check cannot run, return a signal with [Confidence.INCONCLUSIVE] rather than
 *   an empty list, so coverage stays honest;
 * - never throw for an expected condition. The engine isolates failures, but a detector
 *   that throws loses its evidence.
 */
public interface Detector {
    public val id: String
    public val category: Category

    /** Evaluations shallower than this skip the detector. */
    public val minDepth: Depth

    public val budget: Duration get() = DEFAULT_BUDGET

    public suspend fun detect(context: DetectionContext): List<Signal>

    public companion object {
        public val DEFAULT_BUDGET: Duration = 250.milliseconds
    }
}

/** Everything a detector is allowed to reach. */
public interface DetectionContext {
    public val appContext: Context
    public val config: IntegrityConfig
}
