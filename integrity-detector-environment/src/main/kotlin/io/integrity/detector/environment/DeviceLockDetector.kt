package io.integrity.detector.environment

import io.integrity.core.Category
import io.integrity.core.Confidence
import io.integrity.core.Depth
import io.integrity.core.DetectionContext
import io.integrity.core.Detector
import io.integrity.core.Signal
import io.integrity.core.SignalId

/**
 * `ENV_NO_DEVICE_LOCK` — the device has no PIN, pattern or password set.
 *
 * **Evidence.** None beyond the signal itself. The finding is the whole content, and anything
 * further would be describing a person's security habits rather than a device fact.
 *
 * **Expected result.** `CONFIRMED` when there is no device lock — the platform answers this
 * directly, so the reading is exact rather than heuristic. `INCONCLUSIVE` when `KeyguardManager`
 * is unavailable. **No signal at all when the device is secured**, and that direction is the
 * design rather than an omission: a signal that appeared when the device *was* locked would be
 * something in a report raising trust, which hard rule 9 and ADR-0007 forbid outright. This
 * detector can incriminate a device and can never vouch for one.
 *
 * ### Why there is no separate biometric check
 *
 * Android will not enrol a face or a fingerprint without a PIN, pattern or password behind it,
 * so `isDeviceSecure()` is already true whenever a biometric exists. A `ENV_NO_BIOMETRIC_ENROLLED`
 * would therefore add nothing to "is this device locked" while firing on every perfectly secure
 * PIN-only device. Face cannot be isolated in any case: `BiometricManager` reports a STRONG or
 * WEAK class rather than a modality, and `PackageManager.FEATURE_FACE` reports hardware rather
 * than enrolment.
 *
 * **Known bypass.** One framework call, so hooking `isDeviceSecure` to return true is a
 * one-liner — the ceiling every JVM check in this catalogue shares. It raises the cost of a
 * careless setup and produces evidence; it stops nobody competent.
 *
 * **False positives.** High, and made of real people rather than misconfigured devices: shared
 * family tablets, kiosk and single-purpose devices, and users who have simply declined a lock
 * screen. `docs/RISK_SCORING.md` is explicit that a signal of this shape must only ever
 * contribute in combination, and this one ships `INFORMATIONAL` like every other.
 */
internal class DeviceLockDetector(private val probe: DeviceLockProbe? = null) : Detector {

    override val id: String = "environment.device-lock"
    override val category: Category = Category.ENVIRONMENT

    // One framework call with no IO behind it, so it is cheap enough for the startup path.
    override val minDepth: Depth = Depth.QUICK

    override suspend fun detect(context: DetectionContext): List<Signal> {
        val lock = probe ?: RealDeviceLockProbe(context.appContext)

        return when (lock.isDeviceSecure()) {
            // Secured. No signal, deliberately — see the class comment.
            true -> emptyList()
            false -> listOf(signal(Confidence.CONFIRMED, emptyMap()))
            null -> listOf(signal(Confidence.INCONCLUSIVE, mapOf("reason" to "keyguard_unavailable")))
        }
    }

    private fun signal(confidence: Confidence, evidence: Map<String, String>) = Signal(
        id = SignalId.ENV_NO_DEVICE_LOCK,
        category = Category.ENVIRONMENT,
        confidence = confidence,
        evidence = evidence
    )
}
