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

        /** Host misconfiguration, e.g. no signing pin supplied. */
        public val META_CONFIG_INVALID: SignalId = SignalId("META_CONFIG_INVALID")

        // --- ROOT (phase 2) ---------------------------------------------------------

        /** A `su` or related binary exists in a world-readable system location. */
        public val ROOT_SU_BINARY: SignalId = SignalId("ROOT_SU_BINARY")

        /** A known root-manager application is installed and visible to us. */
        public val ROOT_MANAGER_PACKAGE: SignalId = SignalId("ROOT_MANAGER_PACKAGE")

        /** The build advertises itself as a debug/test-signed build. */
        public val ROOT_DANGEROUS_PROPS: SignalId = SignalId("ROOT_DANGEROUS_PROPS")

        // --- Referenced by the scorer's escalation rules ahead of their detectors ------
        // These are decisive on their own, so the scoring model names them directly.
        // Their detectors arrive in phases 4 and 7.

        /** The running APK is not signed by a pinned certificate. */
        public val APP_SIGNATURE_MISMATCH: SignalId = SignalId("APP_SIGNATURE_MISMATCH")

        /** A classes*.dex digest does not match the build-time baseline. */
        public val APP_DEX_DIGEST_MISMATCH: SignalId = SignalId("APP_DEX_DIGEST_MISMATCH")

        /** Play Integrity does not recognise this app: direct repackaging evidence. */
        public val ATT_APP_NOT_RECOGNISED: SignalId = SignalId("ATT_APP_NOT_RECOGNISED")
    }
}
