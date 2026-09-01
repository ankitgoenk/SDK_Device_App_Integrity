package io.integrity.detector.hooking

import java.io.File
import java.security.MessageDigest

/**
 * Seam over `/proc/self/maps`, so the parsing and the allow-list are testable against fixtures
 * captured from real devices rather than only on a hooked phone.
 */
internal interface MapsProbe {
    /** Raw lines of this process's memory map, or null if they cannot be read. */
    fun lines(): List<String>?
}

internal object RealMapsProbe : MapsProbe {
    override fun lines(): List<String>? = runCatching {
        File("/proc/self/maps").readLines()
    }.getOrNull()
}

/** One mapping, reduced to the two things the decision depends on. */
internal class Mapping(val perms: String, val path: String) {

    val isExecutable: Boolean get() = perms.length > 2 && perms[2] == 'x'

    /**
     * Whether this mapping is backed by a real file on disk.
     *
     * The leading slash is not enough, and the exceptions are a **category** rather than a list
     * of quirks: the kernel's anonymous-memory facilities give their regions path-shaped names.
     * ART allocates its JIT cache from exactly those, so every process running managed code
     * carries an executable region whose name begins with a slash and matches no allow-listable
     * prefix. Treating those as files makes this detector fire on every Android device.
     *
     * Which facility ART uses depends on the platform version, and that is why both entries
     * below are needed. Measured 2026-09-02:
     *
     * | Device | Android | JIT cache region |
     * | --- | --- | --- |
     * | Pixel 10a | 16 | `/memfd:jit-cache (deleted)`, `/memfd:jit-zygote-cache (deleted)` |
     * | Xiaomi M2101K6I | 13 | `/memfd:` as above |
     * | Galaxy A50s | 11 | `/dev/ashmem/jit-zygote-cache_4112_4112 (deleted)` |
     *
     * The `ashmem` form appears on **none** of the newer devices, so two reference phones could
     * not have revealed it; a third, older one did, on its first run.
     *
     * A trailing ` (deleted)` on a *real* path stays file-backed: a library unlinked after
     * loading is worth reporting, and no reference capture contains one.
     *
     * Executable anonymous memory is itself worth detecting — it is how an injected agent runs
     * without touching disk — but it is a different check (`HOOK_FRIDA_MAPS` covers RX regions
     * with no backing file) and must not be conflated with "a module was loaded from a path
     * nothing legitimate loads from".
     */
    val isFileBacked: Boolean
        get() = path.startsWith("/") && ANONYMOUS_PREFIXES.none(path::startsWith)

    private companion object {
        /** Kernel anonymous-memory namespaces whose region names look like absolute paths. */
        val ANONYMOUS_PREFIXES = listOf("/memfd:", "/dev/ashmem/")
    }
}

internal object MapsParser {

    /**
     * `address perms offset dev inode path`, with the path optional and allowed to contain
     * spaces. Anonymous regions carry a bracketed name (`[stack]`, `[anon:...]`) which is not
     * a path and must not be treated as one.
     */
    fun parse(lines: List<String>): List<Mapping> = lines.mapNotNull { line ->
        val fields = line.split(WHITESPACE, limit = FIELD_COUNT)
        if (fields.size < FIELD_COUNT) return@mapNotNull null
        val path = fields[FIELD_COUNT - 1].trim()
        if (path.isEmpty()) null else Mapping(fields[1], path)
    }

    private const val FIELD_COUNT = 6
    private val WHITESPACE = Regex("\\s+")
}

/**
 * Paths are digested rather than reported (hard rule 3): a mapping under
 * `/data/data/<package>/…` would otherwise ship the name of an installed application. The
 * backend matches digests against its own list without receiving an inventory.
 *
 * Same construction as `hashPackageName` in `integrity-detector-root` — SHA-256, hex,
 * truncated — so a backend can use one table for both.
 */
internal fun hashPath(path: String): String = MessageDigest.getInstance("SHA-256")
    .digest(path.toByteArray())
    .joinToString("") { "%02x".format(it) }
    .take(PATH_DIGEST_LENGTH)

private const val PATH_DIGEST_LENGTH = 16
