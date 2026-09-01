package io.integrity.detector.root

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import java.io.File
import java.security.MessageDigest

/**
 * Thin seams over the platform so detection logic can be unit-tested against fixtures
 * rather than only on a rooted phone.
 */
internal interface FileProbe {
    fun exists(path: String): Boolean
}

internal interface PackageProbe {
    fun isInstalled(packageName: String): Boolean

    /**
     * Whether a "not installed" answer can be believed.
     *
     * From API 30 package visibility is filtered, and a filtered package is
     * indistinguishable from an absent one. Where that applies, absence is not evidence.
     */
    val absenceIsConclusive: Boolean
}

internal interface BuildProbe {
    val tags: String?
    val type: String?
}

internal object RealFileProbe : FileProbe {
    // exists() throws on some paths under restrictive SELinux policies; that is a "no",
    // not a crash. Note this only ever sees world-readable locations: /data/adb and
    // friends are unreadable to an unprivileged app, which is why they are not probed.
    override fun exists(path: String): Boolean = runCatching { File(path).exists() }.getOrDefault(false)
}

internal class RealPackageProbe(private val context: Context) : PackageProbe {

    override fun isInstalled(packageName: String): Boolean = runCatching {
        context.packageManager.getPackageInfo(packageName, 0)
        true
    }.getOrDefault(false)

    override val absenceIsConclusive: Boolean
        get() = Build.VERSION.SDK_INT < Build.VERSION_CODES.R || hasQueryAllPackages()

    private fun hasQueryAllPackages(): Boolean = runCatching {
        val info = context.packageManager.getPackageInfo(
            context.packageName,
            PackageManager.GET_PERMISSIONS
        )
        info.requestedPermissions?.contains("android.permission.QUERY_ALL_PACKAGES") == true
    }.getOrDefault(false)
}

internal object RealBuildProbe : BuildProbe {
    override val tags: String? get() = Build.TAGS
    override val type: String? get() = Build.TYPE
}

/**
 * Third-party package names never leave the device in the clear (P4): a truncated digest
 * is enough to correlate a device against a known-bad list server-side without shipping an
 * inventory of what someone has installed.
 */
internal fun hashPackageName(packageName: String): String = MessageDigest.getInstance("SHA-256")
    .digest(packageName.toByteArray())
    .joinToString("") { "%02x".format(it) }
    .take(PACKAGE_DIGEST_LENGTH)

/** Long enough to be collision-free against a curated list, short enough to stay coarse. */
private const val PACKAGE_DIGEST_LENGTH = 16

/**
 * The two app-visible surfaces that must agree.
 *
 * Kept as separate seams because the whole detector is the comparison between them: a test
 * that stubbed one would prove nothing.
 */
internal interface BuildFieldProbe {
    /** The value of an `android.os.Build` static field, or null if it cannot be read. */
    fun field(name: String): String?
}

internal interface SystemPropertyProbe {
    /**
     * The raw value of a system property.
     *
     * Empty means **unreadable or unset, not different**. Property reads are labelled by
     * SELinux context: `ro.bootimage.build.fingerprint` returns its value to `adb shell` and
     * an empty string to an app. A comparison that scores empty as a mismatch fires on clean
     * devices — measured, see `docs/TESTING.md` §9.
     */
    fun get(name: String): String?
}

internal object RealBuildFieldProbe : BuildFieldProbe {
    override fun field(name: String): String? = runCatching {
        Build::class.java.getField(name).get(null) as? String
    }.getOrNull()
}

internal object RealSystemPropertyProbe : SystemPropertyProbe {
    override fun get(name: String): String? = runCatching {
        @Suppress("PrivateApi")
        val clazz = Class.forName("android.os.SystemProperties")
        clazz.getMethod("get", String::class.java).invoke(null, name) as? String
    }.getOrNull()
}
