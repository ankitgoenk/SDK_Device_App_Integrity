package io.integrity.detector.emulator

import io.integrity.core.Detector

/**
 * EMU_* and VIRT_* signals: emulators, cloud phones, and virtualised app containers.
 *
 * Phase 0 scaffold: no detectors registered yet. Phase 6 populates this module,
 * one signal family per pull request. Every signal added here must also get a row in
 * docs/DETECTION_CATALOG.md (CI enforces it) and a false-positive analysis in the PR.
 */
public object EmulatorDetectors {

    /**
     * Every detector in this module, for [io.integrity.core.IntegrityConfig.Builder.detectors].
     *
     * Deliberately **not** `@JvmStatic`, unlike the same function on `RootDetectors`,
     * `AppDetectors` and `NativeDetectors`. Adding it is a binary break rather than an
     * addition: on a Kotlin `object` it *replaces* the instance method rather than joining it,
     * so `all()` goes from `public final` to `public static final` and any Java caller holding
     * `Detectors.INSTANCE.all()` gets a `NoSuchMethodError`. The inconsistency is real and
     * worth fixing; it is worth fixing in a deliberate API-break commit, not as a tidy-up.
     */
    public fun all(): List<Detector> = emptyList()
}
