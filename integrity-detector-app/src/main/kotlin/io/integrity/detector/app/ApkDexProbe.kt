package io.integrity.detector.app

import android.content.Context
import java.io.File
import java.io.InputStream
import java.security.MessageDigest
import java.util.zip.ZipFile

/**
 * Seam over reading this app's own APK, so the digesting is testable without a device.
 *
 * [splitCount] is not a detail. The baseline `integrity-baseline-plugin` produces covers the
 * base APK only, so on a split install we are comparing part of an app against a whole one.
 * Reporting the count lets the detector decline rather than accuse.
 */
internal interface ApkDexProbe {

    /** Absolute path of the base APK, or null when the platform will not say. */
    fun baseApkPath(): String?

    /** Number of split APKs installed alongside the base. */
    fun splitCount(): Int
}

internal class RealApkDexProbe(private val context: Context) : ApkDexProbe {

    override fun baseApkPath(): String? = runCatching {
        context.applicationInfo.sourceDir
    }.getOrNull()

    override fun splitCount(): Int = runCatching {
        context.applicationInfo.splitSourceDirs?.size ?: 0
    }.getOrDefault(0)
}

/**
 * Digests the `classes*.dex` entries of an APK and aggregates them with the **shared**
 * [io.integrity.core.DexAggregate], so the client and `integrity-baseline-plugin` cannot
 * compute different values for identical bytes.
 */
internal object ApkDexMeasurement {

    private const val BUFFER_BYTES = 8192
    private const val DEX_PREFIX = "classes"
    private const val DEX_SUFFIX = ".dex"

    /** The aggregate digest and the number of dex entries it covers, or null if unreadable. */
    fun of(apkPath: String): Measurement? = runCatching {
        val perEntry = HashMap<String, String>()
        ZipFile(File(apkPath)).use { zip ->
            zip.entries().toList()
                .filterNot { it.isDirectory }
                .filter { it.name.startsWith(DEX_PREFIX) && it.name.endsWith(DEX_SUFFIX) }
                .forEach { entry -> perEntry[entry.name] = zip.getInputStream(entry).use(::sha256) }
        }
        io.integrity.core.DexAggregate.of(perEntry)
            ?.let { Measurement(digest = it, entryCount = perEntry.size) }
    }.getOrNull()

    class Measurement(val digest: String, val entryCount: Int)

    private fun sha256(stream: InputStream): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(BUFFER_BYTES)
        while (true) {
            val read = stream.read(buffer)
            if (read <= 0) break
            digest.update(buffer, 0, read)
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }
}
