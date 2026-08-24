package io.integrity.detector.root

import io.integrity.core.Detector

/**
 * ROOT_* signals: su/busybox artefacts, Magisk, KernelSU, APatch, dangerous properties, SELinux and verified-boot state, mount anomalies, property spoofing.
 *
 * Phase 0 scaffold: no detectors registered yet. Phase 2 populates this module,
 * one signal family per pull request. Every signal added here must also get a row in
 * docs/DETECTION_CATALOG.md (CI enforces it) and a false-positive analysis in the PR.
 */
public object RootDetectors {

    /** Every detector in this module, for [io.integrity.core.IntegrityConfig.Builder.detectors]. */
    public fun all(): List<Detector> = emptyList()
}
