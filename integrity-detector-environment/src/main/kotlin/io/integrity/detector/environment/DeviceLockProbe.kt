package io.integrity.detector.environment

import android.app.KeyguardManager
import android.content.Context

/**
 * Seam over the platform's lock-screen state, so the decision logic is testable off-device.
 */
internal interface DeviceLockProbe {

    /**
     * Whether a PIN, pattern or password is set, or null when the platform will not say.
     *
     * Null is a real outcome, not a placeholder: without `KeyguardManager` there is nothing to
     * read, and hard rule 2 requires that to surface as `INCONCLUSIVE` rather than as an absence
     * of evidence. The two are the same silence to a reader who only counts signals.
     */
    fun isDeviceSecure(): Boolean?
}

internal class RealDeviceLockProbe(private val context: Context) : DeviceLockProbe {

    /**
     * `isDeviceSecure()` rather than `isKeyguardSecure()`.
     *
     * The older call also returns true for a locked SIM, which is not a device lock and would
     * make this signal silent on a phone that has no screen lock at all. `isDeviceSecure` is
     * API 23 and `minSdk` is 24, so no version gate is needed.
     */
    override fun isDeviceSecure(): Boolean? = runCatching {
        context.getSystemService(KeyguardManager::class.java)?.isDeviceSecure
    }.getOrNull()
}
