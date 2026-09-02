package io.integrity.baseline

import io.integrity.core.DexAggregate
import io.integrity.core.JsonWriter
import java.io.File
import java.io.InputStream
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
     * The value a device compares against, computed by [DexAggregate] — the same code the
     * client runs. A second implementation here is how the build and the device would come to
     * disagree about identical bytes.
     */
    public val dexAggregate: String? get() = DexAggregate.of(dex)

    /**
     * Canonical JSON: keys sorted, no insignificant whitespace, every string escaped.
     *
     * The same discipline `ReportWire` applies for the same reason — this file is compared
     * against something a device reports, and a representation that can render two ways makes
     * a comparison that can answer two ways.
     *
     * **It said that while not doing it.** Keys and `packageName` were interpolated raw
     * between quote characters, so an entry name containing `"` or `\` produced a document no
     * parser accepts. Three of the four interpolated values are hex from `MessageDigest` and
     * could not; the fourth is a zip entry name, which the format constrains only at its ends
     * (`classes*.dex`, `lib/**.so`) and not in between. It does not fire on an ordinary build,
     * and the failure if it ever did would be silent and late: nothing here parses its own
     * output, so the task logs success, the artifact publishes, and the break surfaces at the
     * backend on a release that has already shipped. `IntegrityBaselineTask` already refuses
     * to write a *vacuous* baseline — "a file that looks like a comparison and can never
     * disagree with anything" — and a malformed one is that same file by another route.
     *
     * Escaping goes through [JsonWriter], which `ReportWire` uses, rather than a second
     * implementation: "a writer and a reader with independent notions of what `\u001f` means"
     * is the hazard that extraction exists to remove, and this file is the reader's input.
     */
    public fun toJson(): String = buildString {
        // Keys stay lexicographically sorted: dex < dexAggregate < nativeLibs < packageName.
        append("{")
        append(JsonWriter.string("dex")).append(":")
        appendMap(dex)
        append(",").append(JsonWriter.string("dexAggregate")).append(":")
        append(JsonWriter.string(dexAggregate ?: ""))
        append(",").append(JsonWriter.string("nativeLibs")).append(":")
        appendMap(nativeLibs)
        append(",").append(JsonWriter.string("packageName")).append(":")
        append(JsonWriter.string(packageName))
        append("}")
    }

    private fun StringBuilder.appendMap(entries: Map<String, String>) {
        append(
            entries.entries.sortedBy { it.key }.joinToString(",", "{", "}") { (k, v) ->
                "${JsonWriter.string(k)}:${JsonWriter.string(v)}"
            }
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

    // Duplicated, byte for byte, by `ApkDexMeasurement.sha256` in `integrity-detector-app` —
    // the two halves whose whole point, per `DexAggregate`, is that they cannot compute
    // differently. Both should move next to `DexAggregate` in `integrity-model`.
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
