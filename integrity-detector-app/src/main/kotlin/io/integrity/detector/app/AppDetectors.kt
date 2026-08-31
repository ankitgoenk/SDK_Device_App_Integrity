package io.integrity.detector.app

import io.integrity.core.Detector
import io.integrity.core.IntegrityConfig
import io.integrity.core.Policy
import io.integrity.core.SignalId
import io.integrity.core.Weight

/**
 * APP_* signals: signing-certificate pinning today; dex and native-library digests,
 * unexpected classloaders and the debuggable flag in phase 4.
 *
 * Every check in this module reads from `PackageManager`, which a repackager controls, so
 * treat what lands here as evidence rather than enforcement. The version that an attacker
 * cannot simply hook is the build-time digest baseline verified in native code (phase 4),
 * backed by Play Integrity server-side (phase 7).
 */
public object AppDetectors {

    /** Every detector in this module, for [IntegrityConfig.Builder.detectors]. */
    @JvmStatic
    public fun all(): List<Detector> = listOf(
        SignatureDetector(),
        DexDigestDetector()
    )

    /**
     * Intended weight once shadow-mode data supports promotion. Not applied by default:
     * hard rule 6 keeps new signals INFORMATIONAL so a host cannot enforce on them before
     * it has seen its own distribution.
     */
    @JvmStatic
    public fun proposedWeights(policy: Policy): Policy = policy.withWeight(SignalId.APP_SIGNATURE_MISMATCH, Weight.HIGH)
}
