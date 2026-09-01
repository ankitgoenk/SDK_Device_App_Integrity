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

        /**
         * Package visibility was denied, so package-based results are incomplete.
         *
         * ADR-0004, `INTEGRATION.md` and the `<queries>` manifest fragment all stated that
         * the report carries this. None of them was true: the id did not exist and nothing
         * emitted it, while a filtered probe reported only its own `INCONCLUSIVE` signal.
         *
         * The distinction it restores is the one ADR-0004 cares about: a *specific* check
         * could not see a package, versus **this report as a whole was assembled without
         * package visibility**. A reader of one signal cannot infer the second.
         */
        public val META_VISIBILITY_RESTRICTED: SignalId = SignalId("META_VISIBILITY_RESTRICTED")

        // --- NATIVE CORE (phase 3a) --------------------------------------------------
        // Three of these describe the SDK's own state, not the device's. Only a
        // self-check mismatch is positive evidence about the artifact: a library that
        // fails to load is indistinguishable from a missing ABI, and an attacker who
        // deletes the .so is counting on exactly that ambiguity.

        /** The host did not ask for the native core; its absence is expected. */
        public val META_NATIVE_NOT_CONFIGURED: SignalId = SignalId("META_NATIVE_NOT_CONFIGURED")

        /** The native core loaded but a call into it failed. */
        public val META_NATIVE_FAILED: SignalId = SignalId("META_NATIVE_FAILED")

        /** The loaded native library is not the one this build of the SDK ships. */
        public val APP_NATIVE_LIB_MISMATCH: SignalId = SignalId("APP_NATIVE_LIB_MISMATCH")

        /**
         * This SDK's own executable pages differ from the `.so` they were loaded from.
         *
         * Evidence consistent with post-load code modification. **Not proof of hooking,
         * and its absence is not evidence of a clean process** — GOT/PLT redirection
         * leaves `.text` untouched. See `docs/detectors/HOOK_SELF_TEXT_MISMATCH.md`.
         */
        public val HOOK_SELF_TEXT_MISMATCH: SignalId = SignalId("HOOK_SELF_TEXT_MISMATCH")

        // --- ROOT (phase 2) ---------------------------------------------------------

        /** A `su` or related binary exists in a world-readable system location. */
        public val ROOT_SU_BINARY: SignalId = SignalId("ROOT_SU_BINARY")

        /** A known root-manager application is installed and visible to us. */
        public val ROOT_MANAGER_PACKAGE: SignalId = SignalId("ROOT_MANAGER_PACKAGE")

        /** The build advertises itself as a debug/test-signed build. */
        public val ROOT_DANGEROUS_PROPS: SignalId = SignalId("ROOT_DANGEROUS_PROPS")

        /** `android.os.Build` disagrees with the system property that backs it. */
        public val ROOT_PROP_SPOOF: SignalId = SignalId("ROOT_PROP_SPOOF")

        // --- Referenced by the scorer's escalation rules ahead of their detectors ------
        // These are decisive on their own, so the scoring model names them directly.
        // Their detectors arrive in phases 4 and 7.

        /** The running APK is not signed by a pinned certificate. */
        public val APP_SIGNATURE_MISMATCH: SignalId = SignalId("APP_SIGNATURE_MISMATCH")

        /** A classes*.dex digest does not match the build-time baseline. */
        public val APP_DEX_DIGEST_MISMATCH: SignalId = SignalId("APP_DEX_DIGEST_MISMATCH")

        /**
         * An attestation service does not recognise this app: direct repackaging evidence.
         *
         * Server-side vocabulary, and nothing in this project emits it — ADR-0008 put
         * attestation outside our scope. It stays because the integrator's own attestation
         * *is* in scope for them: this is the `SignalId` under which they feed that verdict
         * into [RiskScorer], where it escalates decisively.
         */
        public val ATT_APP_NOT_RECOGNISED: SignalId = SignalId("ATT_APP_NOT_RECOGNISED")

        // --- SERVER-SIDE VERIFICATION (phase 7) --------------------------------------

        /**
         * A report presented a `keyId` and a signature that did not verify against the key
         * enrolled for it.
         *
         * Server-side vocabulary, and the first one this project actually emits:
         * `sample-backend` raises it during verification, no detector on the device can.
         *
         * **Raised for failing verification, never for the absence of a signature.** An
         * unsigned report is an integration that has not adopted signing, not an attack, and
         * a signal that fired on it would be noise everywhere it matters least. See ADR-0011.
         *
         * Deliberately absent from [RiskScorer.DECISIVE_SIGNALS]. It is real evidence, but
         * key rotation, a restored backup and a cleared Keystore all produce it on ordinary
         * devices, and hard rule 6 ships it at `INFORMATIONAL` until shadow-mode data says
         * otherwise.
         */
        public val SRV_REPORT_SIGNATURE_INVALID: SignalId = SignalId("SRV_REPORT_SIGNATURE_INVALID")
    }
}
