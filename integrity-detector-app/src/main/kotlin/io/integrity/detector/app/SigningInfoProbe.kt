package io.integrity.detector.app

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.annotation.RequiresApi
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

/**
 * Every API-28 call sits behind an inline `Build.VERSION.SDK_INT` check into [Api28].
 * Reading a stored `apiLevel` property instead reads the same to a human but not to Lint,
 * which then flags each member as unguarded against minSdk 24 — and with
 * `warningsAsErrors` that fails the build rather than merely nagging.
 */
internal class RealSigningInfoProbe(private val context: Context) : SigningInfoProbe {

    override val apiLevel: Int = Build.VERSION.SDK_INT

    override fun currentSigners(): List<String>? = runCatching {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            Api28.currentSigners(context)
        } else {
            legacySigners()
        }
    }.getOrNull()

    override fun hasMultipleSigners(): Boolean = runCatching {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            Api28.hasMultipleSigners(context)
        } else {
            false
        }
    }.getOrDefault(false)

    override fun matchesLineage(pinSha256: String): Boolean = runCatching {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            Api28.matchesLineage(context, pinSha256)
        } else {
            // No lineage exists before 28, so a pin can only ever be the current signer,
            // which currentSigners() already covers.
            false
        }
    }.getOrDefault(false)

    @Suppress("DEPRECATION")
    private fun legacySigners(): List<String>? = context.packageManager
        .getPackageInfo(context.packageName, PackageManager.GET_SIGNATURES)
        .signatures
        ?.filterNotNull()
        ?.map { sha256Hex(it.toByteArray()) }
}

@RequiresApi(Build.VERSION_CODES.P)
private object Api28 {

    fun currentSigners(context: Context): List<String>? {
        val signing = signingInfo(context) ?: return null
        return signing.apkContentsSigners?.map { sha256Hex(it.toByteArray()) }
    }

    fun hasMultipleSigners(context: Context): Boolean = signingInfo(context)?.hasMultipleSigners() == true

    // The platform's own rotation-aware check: true for the current signer and for any
    // ancestor in the lineage, which is what makes a pin taken before a legitimate key
    // rotation keep matching afterwards.
    fun matchesLineage(context: Context, pinSha256: String): Boolean = context.packageManager.hasSigningCertificate(
        context.packageName,
        hexToBytes(pinSha256),
        PackageManager.CERT_INPUT_SHA256
    )

    private fun signingInfo(context: Context) = context.packageManager
        .getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        .signingInfo
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
