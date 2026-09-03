package io.integrity.detector.hooking

import io.integrity.core.Detector
import io.integrity.core.Policy
import io.integrity.core.SignalId
import io.integrity.core.Weight

/**
 * HOOK_* signals: Frida, Xposed-family hooking, ART method anomalies, inline and PLT/GOT
 * hooks, debuggers. Most of the work lives in :integrity-native.
 *
 * The family is thinner than the catalogue suggests, and deliberately so. Measured against a
 * resident Xposed framework on 2026-09-01, `HOOK_XPOSED_CLASSES` and `HOOK_XPOSED_STACK` were
 * both blind and `HOOK_XPOSED_ARTEFACTS` turned out to be a duplicate of the mapping check
 * below; all three were cancelled rather than written. See `docs/DETECTION_TRIAGE.md` §7.
 */
public object HookDetectors {

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
    public fun all(): List<Detector> = listOf(
        UnexpectedModuleDetector()
    )

    /**
     * Intended weight once shadow-mode data supports promotion. Not applied by default: hard
     * rule 6 ships every new signal at `INFORMATIONAL`.
     */
    @JvmStatic
    public fun proposedWeights(policy: Policy): Policy = policy
        .withWeight(SignalId.HOOK_UNEXPECTED_MODULE, Weight.HIGH)
}
