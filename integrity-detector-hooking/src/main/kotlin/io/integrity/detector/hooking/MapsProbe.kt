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
     * Whether this mapping is backed by a file on disk.
     *
     * The leading slash is not enough. `memfd_create` gives **anonymous** memory a name that
     * looks exactly like an absolute path, and ART uses it for the JIT: every Android process
     * running managed code carries `/memfd:jit-cache (deleted)` and
     * `/memfd:jit-zygote-cache (deleted)`, both executable and both under no allow-listable
     * prefix. Treating those as files makes this detector fire on every device in existence.
     *
     * A trailing ` (deleted)` on a *real* path is deliberately still file-backed: a library
     * unlinked after loading is a thing worth reporting, and none of the reference captures
     * contains a non-`memfd` deleted mapping.
     */
    val isFileBacked: Boolean get() = path.startsWith("/") && !path.startsWith(MEMFD_PREFIX)

    private companion object {
        const val MEMFD_PREFIX = "/memfd:"
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
