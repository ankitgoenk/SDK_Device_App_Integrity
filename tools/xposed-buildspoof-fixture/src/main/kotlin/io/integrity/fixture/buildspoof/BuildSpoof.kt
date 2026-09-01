package io.integrity.fixture.buildspoof

import android.os.Build
import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.callbacks.XC_LoadPackage
import java.lang.reflect.Field
import java.lang.reflect.Modifier

/**
 * The positive control for the `Build`-versus-property check.
 *
 * Rewrites `android.os.Build.FINGERPRINT` and friends in the target process and **deliberately
 * leaves `ro.build.fingerprint` alone** — reproducing what Play Integrity Fork does to
 * `com.google.android.gms.unstable`, aimed at an app we control so the divergence is observable.
 *
 * `Build.FINGERPRINT` is `static final` but assigned at runtime from `SystemProperties`, so it
 * is not a compile-time constant and is not inlined into readers. Rewriting it here is visible
 * to code that reads it afterwards, which is the whole point.
 */
class BuildSpoof : IXposedHookLoadPackage {

    override fun handleLoadPackage(lpparam: XC_LoadPackage.LoadPackageParam) {
        if (lpparam.packageName != TARGET) return
        SPOOFED.forEach { (name, value) -> overwrite(name, value) }
    }

    private fun overwrite(fieldName: String, value: String) {
        runCatching {
            val field: Field = Build::class.java.getDeclaredField(fieldName)
            field.isAccessible = true
            // Clear FINAL where the runtime still honours it; harmless where it does not.
            runCatching {
                val modifiers = Field::class.java.getDeclaredField("accessFlags")
                modifiers.isAccessible = true
                modifiers.setInt(field, field.modifiers and Modifier.FINAL.inv())
            }
            field.set(null, value)
        }
    }

    private companion object {
        const val TARGET = "io.integrity.sample"

        /** Deliberately a different device, so a partial spoof is obvious in the evidence. */
        val SPOOFED = mapOf(
            "FINGERPRINT" to "google/husky/husky:14/AP1A.240405.002/11480754:user/release-keys",
            "MODEL" to "Pixel 8 Pro",
            "DEVICE" to "husky",
            "PRODUCT" to "husky"
        )
    }
}
