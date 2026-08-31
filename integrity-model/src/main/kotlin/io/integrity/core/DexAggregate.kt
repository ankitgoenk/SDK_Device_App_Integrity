package io.integrity.core

import java.security.MessageDigest

/**
 * One bounded digest over a set of `classes*.dex` entries.
 *
 * Lives here, in the module the backend shares verbatim, because **the build and the device
 * must compute this identically or the comparison is meaningless**. `integrity-baseline-plugin`
 * aggregates what it packaged; the client aggregates what it is running; a backend compares the
 * two. Three parties, one construction — and the alternative, a copy in each, is exactly the
 * "two implementations of one format" failure this module exists to prevent.
 *
 * The construction:
 *
 * 1. **Sorted by entry name.** Zip order is not a contract and neither is map iteration order.
 * 2. **`name:digest` joined by newline.** Framing, not decoration: without the name in the
 *    input, two archives with the same digests under different names would aggregate equal.
 * 3. **SHA-256 of the UTF-8 bytes**, rendered lower-case hex.
 *
 * Bounded on purpose. A real APK carries nine dex entries, and reporting each one is ~600 bytes
 * of evidence for a signal whose evidence is meant to be small. What it costs is knowing which
 * entry moved; no decision reads that, and a backend holding the per-entry baseline can work it
 * out without the device sending it.
 */
public object DexAggregate {

    /** Null when [perEntry] is empty: nothing measured must never produce a comparable value. */
    public fun of(perEntry: Map<String, String>): String? {
        if (perEntry.isEmpty()) return null
        val canonical = perEntry.entries
            .sortedBy { it.key }
            .joinToString("\n") { "${it.key}:${it.value}" }
        return MessageDigest.getInstance("SHA-256")
            .digest(canonical.encodeToByteArray())
            .joinToString("") { "%02x".format(it) }
    }
}
