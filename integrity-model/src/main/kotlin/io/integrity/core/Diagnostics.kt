package io.integrity.core

/**
 * What happened to one detector during one evaluation.
 *
 * This is **not** evidence and never travels in a report. See [IntegrityDiagnostics].
 */
public class DetectorRun(
    /** The detector's stable id, e.g. `root.su-binary`. */
    public val detectorId: String,
    public val category: Category,
    /** The lowest [Depth] at which this detector runs at all. */
    public val minDepth: Depth,
    public val outcome: RunOutcome,
    /** How many signals it emitted. Zero is the common case and means nothing on its own. */
    public val signalCount: Int,
    /** Wall-clock milliseconds, or -1 when the detector never ran. */
    public val durationMillis: Long
)

/** Why a detector produced what it produced. */
public enum class RunOutcome {
    /** Not applicable at the requested [Depth]; it was never invoked. */
    SKIPPED_FOR_DEPTH,

    /**
     * Ran to completion and emitted nothing.
     *
     * **This does not mean the device is clean for this check.** A detector emits nothing when
     * it looked and found no evidence, and a compromised device that successfully hides
     * produces exactly this outcome. It is indistinguishable from a healthy one by design —
     * see ADR-0007.
     */
    FOUND_NOTHING,

    /** Ran and emitted at least one non-`INCONCLUSIVE` signal. */
    EMITTED_EVIDENCE,

    /** Ran but could not determine anything; every signal it emitted was `INCONCLUSIVE`. */
    INCONCLUSIVE,

    /** Exceeded its time budget. */
    TIMED_OUT,

    /** Threw. */
    FAILED
}

/**
 * A description of what the SDK just did, for humans.
 *
 * ### Why this is not part of `IntegrityReport`
 *
 * It would be a bypass. Hard rule 9 and ADR-0007 say nothing in a report may raise trust, and a
 * list reading "eighteen checks ran, seventeen found nothing" raises trust in exactly the way
 * those rules forbid: a stripped SDK emitting that list earns the same finding as a healthy
 * device, and the list is cheaper to forge than the evidence it stands in for. `coverage`
 * already carries the only server-safe part of this — the *fraction* that concluded — and
 * `docs/TESTING.md` §9 records why even that must not be read as threat coverage.
 *
 * So diagnostics are delivered to the **host**, in-process, through
 * [IntegrityConfig.Builder.diagnosticsSink]. They are for a QA build, a bug report, or a tester
 * running the sample app on hardware the team does not own. They are not serialised by
 * `ReportWire`, not signed, and not accepted by the backend.
 *
 * **Read [RunOutcome.FOUND_NOTHING] carefully.** It is the most common outcome and the least
 * informative one.
 */
public class IntegrityDiagnostics(
    public val depth: Depth,
    public val reportId: String,
    public val runs: List<DetectorRun>,
    public val sdkVersion: String
) {
    /** Detectors that emitted at least one non-`INCONCLUSIVE` signal. */
    public val withEvidence: List<DetectorRun>
        get() = runs.filter { it.outcome == RunOutcome.EMITTED_EVIDENCE }

    /** Detectors that could not reach a conclusion, for any reason. */
    public val unableToConclude: List<DetectorRun>
        get() = runs.filter {
            it.outcome == RunOutcome.INCONCLUSIVE ||
                it.outcome == RunOutcome.TIMED_OUT ||
                it.outcome == RunOutcome.FAILED
        }
}
