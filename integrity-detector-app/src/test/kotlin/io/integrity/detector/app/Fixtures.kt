package io.integrity.detector.app

import android.content.Context
import io.integrity.core.DetectionContext
import io.integrity.core.IntegrityConfig

internal val APP_SIGNING_KEY = "AA".repeat(32)
internal val ROTATED_FROM_KEY = "BB".repeat(32)
internal val UPLOAD_KEY = "CC".repeat(32)
internal val ATTACKER_KEY = "DD".repeat(32)

internal class FakeSigningInfoProbe(
    override val apiLevel: Int = 34,
    private val signers: List<String>? = listOf(APP_SIGNING_KEY),
    private val lineage: Set<String> = emptySet(),
    private val multipleSigners: Boolean = false
) : SigningInfoProbe {
    override fun currentSigners(): List<String>? = signers
    override fun hasMultipleSigners(): Boolean = multipleSigners

    // Mirrors the platform: true for the current signer and for any ancestor.
    override fun matchesLineage(pinSha256: String): Boolean =
        pinSha256 in lineage || signers?.contains(pinSha256) == true
}

internal class FakeDetectionContext(override val config: IntegrityConfig) : DetectionContext {
    override val appContext: Context
        get() = error("a unit test must not need a real Context")
}

internal fun configPinning(vararg pins: String): IntegrityConfig =
    IntegrityConfig.Builder().expectedSigningCertSha256(*pins).build()
