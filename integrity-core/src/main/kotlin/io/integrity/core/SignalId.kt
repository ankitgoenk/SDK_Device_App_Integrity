package io.integrity.core

/**
 * Stable identifier for a detection signal.
 *
 * The string value is contract: it appears in reports, backend rules and dashboards.
 * Ids are added and deprecated, never renamed or renumbered. Every id must have a row
 * in docs/DETECTION_CATALOG.md — CI enforces this.
 */
@JvmInline
public value class SignalId(public val value: String) {

    override fun toString(): String = value

    public companion object {
        // --- META -------------------------------------------------------
        // Detector families arrive in phases 2-7; see docs/PLAN.md.

        /** A detector exceeded its time budget; its evidence was lost. */
        public val META_DETECTOR_TIMEOUT: SignalId = SignalId("META_DETECTOR_TIMEOUT")

        /** A detector threw. Evidence carries the exception class only. */
        public val META_DETECTOR_ERROR: SignalId = SignalId("META_DETECTOR_ERROR")

        /** Native library missing or failed self-check — a common bypass, so it scores high. */
        public val META_NATIVE_UNAVAILABLE: SignalId = SignalId("META_NATIVE_UNAVAILABLE")

        /** Package visibility denied, so ENV_* results are incomplete. */
        public val META_VISIBILITY_RESTRICTED: SignalId = SignalId("META_VISIBILITY_RESTRICTED")

        /** Host misconfiguration, e.g. no signing pin supplied. */
        public val META_CONFIG_INVALID: SignalId = SignalId("META_CONFIG_INVALID")

        /** Scaffold only: the engine has not been implemented yet (phase 1). */
        public val META_ENGINE_NOT_IMPLEMENTED: SignalId = SignalId("META_ENGINE_NOT_IMPLEMENTED")
    }
}
