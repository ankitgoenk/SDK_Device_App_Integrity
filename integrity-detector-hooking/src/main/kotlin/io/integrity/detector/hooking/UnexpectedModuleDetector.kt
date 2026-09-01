package io.integrity.detector.hooking

import io.integrity.core.Category
import io.integrity.core.Confidence
import io.integrity.core.Depth
import io.integrity.core.DetectionContext
import io.integrity.core.Detector
import io.integrity.core.Signal
import io.integrity.core.SignalId

/**
 * `HOOK_UNEXPECTED_MODULE` — executable code is mapped into this process from a path no
 * legitimate library lives under.
 *
 * **Evidence.** How many such mappings, truncated digests of their paths, and whether any sits
 * in the root-module directory. Never the paths themselves: one under `/data/data/<package>/`
 * would ship the name of an installed application (hard rule 3).
 *
 * **Expected result.** `CONFIRMED` when a mapping comes from `/data/adb` or `/data/local/tmp` —
 * the root-module directory and the classic injection staging directory, neither of which any
 * app library is loaded from. `LIKELY` otherwise, because an unrecognised prefix might be an
 * OEM injecting its own library rather than an attacker. `INCONCLUSIVE` when the map cannot be
 * read, and **no signal** when nothing is unexpected.
 *
 * ### Two qualifiers carry this detector
 *
 * The idea "modules outside an allow-list" was `DEFER`red because the allow-list was the whole
 * problem: matching *every* mapping leaves **113 unexplained paths on the Pixel and 28 on the
 * Xiaomi** — ART heap regions, `dalvik-cache` artefacts, `frro`/`idmap` overlays. Requiring the
 * mapping to be both **executable** and **file-backed** drops that to **zero on both**, because
 * heap regions are anonymous and resource overlays are not executable. Neither class had to be
 * enumerated. Measured, see `docs/TESTING.md` §9.
 *
 * The final allow-list entry is not cosmetic either. `/data/misc/apexdata/com.android.art/`
 * holds ART's compiled boot image and appears on the Xiaomi but **never** on the Pixel; a rule
 * validated on one device would fire on every phone with a separately-compiled boot image.
 *
 * **Known bypass.** Nothing forces a framework to stay resident. ReZygisk unloads from the
 * forked child after injecting and is completely invisible here — this catches residents, not
 * visitors. A framework free to stage its library under `/data/app` defeats the prefix list, and
 * one that scrubs its own maps entry defeats the whole approach; no such framework was found on
 * the reference hardware, which is why `HOOK_MAPS_INCONSISTENT` remains unbuildable.
 *
 * **False positives.** None on either reference device, hooked or clean. The residual risk is an
 * OEM mapping its own library from an unrecognised prefix, which is why only the two
 * unambiguous directories escalate to `CONFIRMED`.
 */
internal class UnexpectedModuleDetector(private val maps: MapsProbe = RealMapsProbe) : Detector {

    override val id: String = "hooking.unexpected-module"
    override val category: Category = Category.HOOKING
    override val minDepth: Depth = Depth.STANDARD

    override suspend fun detect(context: DetectionContext): List<Signal> {
        val lines = maps.lines()
            ?: return listOf(
                Signal(
                    id = SignalId.HOOK_UNEXPECTED_MODULE,
                    category = Category.HOOKING,
                    confidence = Confidence.INCONCLUSIVE,
                    evidence = mapOf("reason" to "maps_unreadable")
                )
            )

        val unexpected = MapsParser.parse(lines)
            .filter { it.isExecutable && it.isFileBacked }
            .map { it.path }
            .filterNot { path -> EXPECTED_PREFIXES.any(path::startsWith) }
            .distinct()

        if (unexpected.isEmpty()) return emptyList()

        val decisive = unexpected.any { path -> DECISIVE_PREFIXES.any(path::startsWith) }

        return listOf(
            Signal(
                id = SignalId.HOOK_UNEXPECTED_MODULE,
                category = Category.HOOKING,
                confidence = if (decisive) Confidence.CONFIRMED else Confidence.LIKELY,
                evidence = mapOf(
                    "count" to unexpected.size.toString(),
                    "digests" to unexpected.take(MAX_REPORTED).joinToString(",", transform = ::hashPath),
                    "rootModuleDir" to decisive.toString()
                )
            )
        )
    }

    private companion object {
        /**
         * Where executable code legitimately comes from. Every entry was measured present on at
         * least one reference device; none is speculative.
         */
        val EXPECTED_PREFIXES = listOf(
            "/system",
            "/apex",
            "/vendor",
            "/product",
            "/system_ext",
            // The app's own libraries, whether extracted or mapped straight out of the APK.
            "/data/app",
            // ART's compiled boot image. Present on the Xiaomi, absent on the Pixel.
            "/data/misc/apexdata/com.android.art/"
        )

        /**
         * No application library is ever loaded from these. `/data/adb` is where KernelSU and
         * Magisk keep modules; `/data/local/tmp` is where injected agents are staged.
         */
        val DECISIVE_PREFIXES = listOf("/data/adb", "/data/local/tmp")

        /** Evidence stays bounded; the count carries the rest. */
        const val MAX_REPORTED = 8
    }
}
