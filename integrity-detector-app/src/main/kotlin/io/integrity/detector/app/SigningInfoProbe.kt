package io.integrity.detector.app

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import java.security.MessageDigest

/**
 * Seam over the platform's signing APIs, which differ materially by API level.
 */
internal interface SigningInfoProbe {

    val apiLevel: Int

    /**
     * SHA-256 digests (uppercase hex, no separators) of the certificates currently
     * signing this APK, or null when the platform cannot tell us.
     */
    fun currentSigners(): List<String>?

    /** True when an APK signed by more than one certificate is reported. */
    fun hasMultipleSigners(): Boolean

    /**
     * Whether the platform recognises [pinSha256] as the current signer *or* an ancestor
     * in the signing lineage. Only meaningful from API 28; older levels have no lineage.
     */
    fun matchesLineage(pinSha256: String): Boolean
}

internal class RealSigningInfoProbe(private val context: Context) : SigningInfoProbe {

    override val apiLevel: Int = Build.VERSION.SDK_INT

    override fun currentSigners(): List<String>? = runCatching {
        val pm = context.packageManager
        if (apiLevel >= Build.VERSION_CODES.P) {
            val info = pm.getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
            val signing = info.signingInfo ?: return null
            val certs = if (signing.hasMultipleSigners()) {
                signing.apkContentsSigners
            } else {
                // Current signer first; history is consulted separately via matchesLineage.
                signing.apkContentsSigners
            }
            certs?.map { sha256Hex(it.toByteArray()) }
        } else {
            @Suppress("DEPRECATION")
            val info = pm.getPackageInfo(context.packageName, PackageManager.GET_SIGNATURES)
            @Suppress("DEPRECATION")
            info.signatures?.filterNotNull()?.map { sha256Hex(it.toByteArray()) }
        }
    }.getOrNull()

    override fun hasMultipleSigners(): Boolean = runCatching {
        if (apiLevel < Build.VERSION_CODES.P) return false
        val info = context.packageManager
            .getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        info.signingInfo?.hasMultipleSigners() == true
    }.getOrDefault(false)

    override fun matchesLineage(pinSha256: String): Boolean = runCatching {
        if (apiLevel < Build.VERSION_CODES.P) return false
        // The platform's own rotation-aware check: true for the current signer and for any
        // ancestor in the lineage, which is exactly what makes legitimate key rotation
        // survive a pin taken before the rotation.
        context.packageManager.hasSigningCertificate(
            context.packageName,
            hexToBytes(pinSha256),
            PackageManager.CERT_INPUT_SHA256
        )
    }.getOrDefault(false)
}

internal fun sha256Hex(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
    .digest(bytes)
    .joinToString("") { "%02X".format(it) }

private const val HEX_RADIX = 16
private const val HEX_CHARS_PER_BYTE = 2
private const val NIBBLE_BITS = 4

internal fun hexToBytes(hex: String): ByteArray {
    val clean = hex.replace(":", "").trim()
    return ByteArray(clean.length / HEX_CHARS_PER_BYTE) { index ->
        val high = Character.digit(clean[index * HEX_CHARS_PER_BYTE], HEX_RADIX)
        val low = Character.digit(clean[index * HEX_CHARS_PER_BYTE + 1], HEX_RADIX)
        ((high shl NIBBLE_BITS) + low).toByte()
    }
}
