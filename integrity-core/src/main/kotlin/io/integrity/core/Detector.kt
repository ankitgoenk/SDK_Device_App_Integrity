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

    /**
     * The detector's own family, for grouping it in [IntegrityDiagnostics].
     *
     * **Not a claim that every signal it emits carries this category**, and reading it as one
     * is the mistake this doc exists to prevent. Three shipped cases already differ, two of
     * them by design: `RootManagerPackageDetector` is `ROOT` and emits
     * `META_VISIBILITY_RESTRICTED` alongside its own finding, because those answer different
     * questions; `NativeIntegrityDetector` is `META` and emits `APP_NATIVE_LIB_MISMATCH` as
     * `APP_TAMPER`, because three of its four outcomes describe the SDK and the fourth
     * describes the artifact; and [DetectionEngine] attributes `META_DETECTOR_TIMEOUT` and
     * `META_DETECTOR_ERROR` to whichever detector produced them, whatever family it belongs to.
     *
     * Scoring never reads this. `RiskScorer` keys on [Signal.category], which defaults to the
     * one the signal's id implies. This is a label for a human reading a diagnostics dump, and
     * it is still needed for a detector that emitted nothing at all — a `SKIPPED_FOR_DEPTH`
     * run has no signal to derive a family from.
     */
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
