package io.integrity.detector.root

import io.integrity.core.Category
import io.integrity.core.Confidence
import io.integrity.core.Depth
import io.integrity.core.DetectionContext
import io.integrity.core.Detector
import io.integrity.core.Signal
import io.integrity.core.SignalId

/**
 * ROOT_SU_BINARY — a `su`, `magisk` or `busybox` binary in a world-readable system path.
 *
 * **Evidence.** `artefact` (one of `su`, `magisk`, `busybox`) and `matches` (a count).
 * Never the path itself: paths are exactly the sort of detail privacy rule P5 keeps out of
 * reports, and the artefact class is what a backend rule actually needs.
 *
 * **Expected result.** A `su` or `magisk` binary is CONFIRMED — stock builds do not ship
 * one. `busybox` alone is POSSIBLE: some legitimate ROMs and TV boxes include it.
 * Finding nothing is a conclusive negative for *these paths*, which is a much weaker claim
 * than "not rooted"; see the bypass note.
 *
 * **Known bypass.** Trivial for anyone trying. Magisk's DenyList unmounts its own artefacts
 * from the app's namespace, so a hidden Magisk install shows nothing here. anything under `/data/adb`
 * or `/sbin` is not readable by an unprivileged app at all, so this only ever sees
 * sloppy or legacy setups. Real root detection comes from the native mount-table and
 * property-divergence checks in phase 3, and from Play Integrity server-side.
 *
 * **False positives.** Low but not zero: developer and engineering ROMs, some Android TV
 * and set-top images, and a few emulator system images ship `su` or `busybox` in
 * `/system/xbin`. That is why `busybox` alone is only POSSIBLE.
 */
internal class SuBinaryDetector(private val files: FileProbe = RealFileProbe) : Detector {

    override val id: String = "root.su-binary"
    override val category: Category = Category.ROOT
    override val minDepth: Depth = Depth.STANDARD

    override suspend fun detect(context: DetectionContext): List<Signal> {
        val found = ARTEFACTS.filterValues { paths -> paths.any(files::exists) }.keys
        if (found.isEmpty()) return emptyList()

        val decisive = found.any { it != ARTEFACT_BUSYBOX }
        return listOf(
            Signal(
                id = SignalId.ROOT_SU_BINARY,
                category = Category.ROOT,
                confidence = if (decisive) Confidence.CONFIRMED else Confidence.POSSIBLE,
                evidence = mapOf(
                    "artefact" to found.sorted().joinToString(","),
                    "matches" to found.size.toString()
                )
            )
        )
    }

    private companion object {
        const val ARTEFACT_BUSYBOX = "busybox"

        // World-readable locations only. /data/adb, /sbin and /su are not statable by an
        // unprivileged app, so probing them would produce a check that always says "no".
        val ARTEFACTS: Map<String, List<String>> = mapOf(
            "su" to listOf(
                "/system/bin/su",
                "/system/xbin/su",
                "/system/sbin/su",
                "/system/sd/xbin/su",
                "/system/bin/failsafe/su",
                "/system/usr/we-need-root/su",
                "/vendor/bin/su",
                "/product/bin/su"
            ),
            "magisk" to listOf(
                "/system/bin/magisk",
                "/system/xbin/magisk",
                "/system/bin/magiskpolicy",
                "/system/xbin/magiskpolicy"
            ),
            ARTEFACT_BUSYBOX to listOf(
                "/system/bin/busybox",
                "/system/xbin/busybox",
                "/vendor/bin/busybox"
            )
        )
    }
}
