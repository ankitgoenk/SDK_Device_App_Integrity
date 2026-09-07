package io.integrity.detector.environment

import io.integrity.core.Detector
import io.integrity.core.Policy
import io.integrity.core.SignalId
import io.integrity.core.Weight

/**
 * ENV_* signals: device lock state today; hostile co-installed apps, ADB state, the user CA
 * store, overlays, screen capture and accessibility services still to come.
 *
 * Phase 5 populates this module, one signal family per pull request. Every signal added here
 * must also get a row in docs/DETECTION_CATALOG.md (CI enforces it) and a false-positive
 * analysis in the PR.
 *
 * Note what this family is and is not. `ENV_*` describes the environment a healthy app finds
 * itself in, which means most of it is *posture* rather than compromise, and posture has a far
 * larger legitimate population than root or hooking does. `docs/RISK_SCORING.md` names the
 * discipline that follows: never enforce on one of these alone.
 */
public object EnvironmentDetectors {

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
        DeviceLockDetector()
    )

    /**
     * Intended weight once shadow-mode data supports promotion. Not applied by default: hard
     * rule 6 ships every new signal at `INFORMATIONAL`.
     *
     * `LOW` rather than anything higher, and it is unlikely to move. The false-positive
     * population here is not misconfigured devices but people — shared tablets, kiosks, anyone
     * who declined a lock screen — so this is a combination signal by construction.
     */
    @JvmStatic
    public fun proposedWeights(policy: Policy): Policy = policy
        .withWeight(SignalId.ENV_NO_DEVICE_LOCK, Weight.LOW)
}
