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

    /** Every detector in this module, for [io.integrity.core.IntegrityConfig.Builder.detectors]. */
    public fun all(): List<Detector> = emptyList()
}
