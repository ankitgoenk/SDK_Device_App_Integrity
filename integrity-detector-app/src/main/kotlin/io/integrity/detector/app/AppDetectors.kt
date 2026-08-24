package io.integrity.detector.app

import io.integrity.core.Detector

/**
 * APP_* signals: signing-certificate pinning, dex and native-library digests, unexpected classloaders, debuggable flag, repackaging.
 *
 * Phase 0 scaffold: no detectors registered yet. Phase 4 populates this module,
 * one signal family per pull request. Every signal added here must also get a row in
 * docs/DETECTION_CATALOG.md (CI enforces it) and a false-positive analysis in the PR.
 */
public object AppDetectors {

    /** Every detector in this module, for [io.integrity.core.IntegrityConfig.Builder.detectors]. */
    public fun all(): List<Detector> = emptyList()
}
