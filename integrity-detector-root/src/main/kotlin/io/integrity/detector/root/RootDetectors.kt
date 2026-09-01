package io.integrity.detector.root

import io.integrity.core.Detector
import io.integrity.core.IntegrityConfig
import io.integrity.core.Policy
import io.integrity.core.SignalId
import io.integrity.core.Weight

/**
 * ROOT_* signals: su/busybox artefacts, root-manager packages and dangerous build
 * properties.
 *
 * These are the JVM-layer root checks, and they are the weakest ones in the catalog: every
 * one of them is defeated by Magisk's DenyList or by `resetprop`. They are here because
 * they are cheap, testable and catch unsophisticated setups. The root signals with real
 * teeth — mount-table anomalies, property divergence, verified-boot state — need the native
 * core and land in phase 3, and the authoritative answer comes from Play Integrity
 * server-side in phase 7.
 */
public object RootDetectors {

    /** Every detector in this module, for [IntegrityConfig.Builder.detectors]. */
    @JvmStatic
    public fun all(): List<Detector> = listOf(
        SuBinaryDetector(),
        RootManagerPackageDetector(),
        DangerousPropertiesDetector(),
        PropertySpoofDetector()
    )

    /**
     * Intended weights once shadow-mode data supports promotion.
     *
     * They are not applied by default: hard rule 6 says a new signal ships INFORMATIONAL,
     * so a host that enables these before it has seen its own distribution cannot lock
     * anyone out with them.
     */
    @JvmStatic
    public fun proposedWeights(policy: Policy): Policy = policy
        .withWeight(SignalId.ROOT_SU_BINARY, Weight.HIGH)
        .withWeight(SignalId.ROOT_MANAGER_PACKAGE, Weight.MEDIUM)
        .withWeight(SignalId.ROOT_DANGEROUS_PROPS, Weight.LOW)
        .withWeight(SignalId.ROOT_PROP_SPOOF, Weight.HIGH)
}
