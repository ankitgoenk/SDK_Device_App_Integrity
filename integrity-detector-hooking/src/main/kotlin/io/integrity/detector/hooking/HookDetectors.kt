package io.integrity.detector.hooking

import io.integrity.core.Detector

/**
 * HOOK_* signals: Frida, Xposed-family hooking, ART method anomalies, inline and PLT/GOT
 * hooks, debuggers. Most of the work lives in :integrity-native.
 *
 * Phase 0 scaffold: no detectors registered yet. Phase 3 populates this module,
 * one signal family per pull request. Every signal added here must also get a row in
 * docs/DETECTION_CATALOG.md (CI enforces it) and a false-positive analysis in the PR.
 */
public object HookDetectors {

    /** Every detector in this module, for [io.integrity.core.IntegrityConfig.Builder.detectors]. */
    public fun all(): List<Detector> = emptyList()
}
