package io.integrity.baseline

import java.io.File
import java.security.MessageDigest
import java.util.zip.ZipFile

/**
 * What a build produced, digested.
 *
 * Pure and Gradle-free so the interesting half is unit-testable without a build: the digesting
 * is the part that can be wrong, and a test that needs an Android project to run is a test
 * nobody runs.
 */
public data class Baseline(
    public val packageName: String,
    public val dex: Map<String, String>,
    public val nativeLibs: Map<String, String>
) {

    /**
     * Canonical JSON: keys sorted, no insignificant whitespace.
     *
     * The same discipline `ReportWire` applies for the same reason — this file is compared
     * against something a device reports, and a representation that can render two ways
     * makes a comparison that can answer two ways.
     */
    public fun toJson(): String = buildString {
        append("""{"dex":""")
        appendMap(dex)
        append(""","nativeLibs":""")
        appendMap(nativeLibs)
        append(""","packageName":"""")
        append(packageName)
        append(""""}""")
    }

    private fun StringBuilder.appendMap(entries: Map<String, String>) {
        append(
            entries.entries.sortedBy { it.key }.joinToString(",", "{", "}") { (k, v) -> """"$k":"$v"""" }
        )
    }
}

/**
 * Digests the parts of a packaged artifact that a tampered build would change.
 *
 * **What this is for, stated narrowly.** The output is a *build* artifact consumed by the
 * backend, not something embedded in the APK. A digest of the APK cannot live inside that APK,
 * and a baseline the attacker ships alongside the code they rewrote is worth nothing: they
 * would simply regenerate it. So the client measures its own dex at runtime and reports what
 * it found, and only a party holding this file independently can say the report is wrong —
 * which is ADR-0006's division of labour and ADR-0007's asymmetry, arrived at by arithmetic
 * rather than by preference.
 */
public object BaselineComputer {

    private const val DEX_PREFIX = "classes"
    private const val DEX_SUFFIX = ".dex"
    private const val LIB_PREFIX = "lib/"
    private const val LIB_SUFFIX = ".so"
    private const val BUFFER_BYTES = 8192

    public fun compute(archive: File, packageName: String): Baseline {
        val dex = LinkedHashMap<String, String>()
        val libs = LinkedHashMap<String, String>()

        ZipFile(archive).use { zip ->
            val entries = zip.entries().toList()
                .filterNot { it.isDirectory }
                // Sorted so the walk order of the archive cannot change the output. Zip entry
                // order is not a contract, and this file is diffed across builds.
                .sortedBy { it.name }
            for (entry in entries) {
                val target = bucketFor(entry.name, dex, libs)
                target?.put(entry.name, zip.getInputStream(entry).use { sha256(it) })
            }
        }
        return Baseline(packageName = packageName, dex = dex, nativeLibs = libs)
    }

    /** Which map an entry belongs in, or null when it is not part of the baseline. */
    private fun bucketFor(
        name: String,
        dex: MutableMap<String, String>,
        libs: MutableMap<String, String>
    ): MutableMap<String, String>? = when {
        name.startsWith(DEX_PREFIX) && name.endsWith(DEX_SUFFIX) -> dex
        name.startsWith(LIB_PREFIX) && name.endsWith(LIB_SUFFIX) -> libs
        else -> null
    }

    private fun sha256(stream: java.io.InputStream): String {
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
