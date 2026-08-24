package io.integrity.detector.environment

import io.integrity.core.Detector

/**
 * ENV_* signals: hostile co-installed apps, ADB state, user CA store, overlays, screen capture, accessibility services.
 *
 * Phase 0 scaffold: no detectors registered yet. Phase 5 populates this module,
 * one signal family per pull request. Every signal added here must also get a row in
 * docs/DETECTION_CATALOG.md (CI enforces it) and a false-positive analysis in the PR.
 */
public object EnvironmentDetectors {

    /** Every detector in this module, for [io.integrity.core.IntegrityConfig.Builder.detectors]. */
    public fun all(): List<Detector> = emptyList()
}
