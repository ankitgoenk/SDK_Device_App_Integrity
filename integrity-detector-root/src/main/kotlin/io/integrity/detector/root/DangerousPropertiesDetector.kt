package io.integrity.detector.root

import io.integrity.core.Category
import io.integrity.core.Confidence
import io.integrity.core.Depth
import io.integrity.core.DetectionContext
import io.integrity.core.Detector
import io.integrity.core.Signal
import io.integrity.core.SignalId

/**
 * ROOT_DANGEROUS_PROPS — the build advertises itself as test-signed or a debug build.
 *
 * **Evidence.** `tags` and `buildType`, both build properties rather than anything about
 * the user, so they are safe to report verbatim.
 *
 * **Expected result.** POSSIBLE, never higher. A `test-keys` build is a signal about how
 * the ROM was signed, not proof that anything is wrong with this device right now.
 *
 * **Known bypass.** `resetprop` rewrites these values in seconds, and hiding modules do it
 * by default, so a determined user shows `release-keys` regardless. The check that catches
 * that is the native comparison of `__system_property_get` against the on-disk values
 * (ROOT_PROP_SPOOF, phase 3) — this JVM check only reads what the system chooses to say.
 *
 * **False positives.** The highest of the three root signals, and the reason this ships at
 * INFORMATIONAL. Budget devices from several manufacturers, many Android TV and set-top
 * images, and most emulator images ship `test-keys` while being entirely stock and
 * unmodified. Enforcing on this alone would lock out whole market segments.
 */
internal class DangerousPropertiesDetector(private val build: BuildProbe = RealBuildProbe) : Detector {

    override val id: String = "root.dangerous-properties"
    override val category: Category = Category.ROOT
    override val minDepth: Depth = Depth.QUICK

    override suspend fun detect(context: DetectionContext): List<Signal> {
        val tags = build.tags
        val type = build.type
        if (tags == null && type == null) {
            return listOf(
                Signal(
                    id = SignalId.ROOT_DANGEROUS_PROPS,
                    category = Category.ROOT,
                    confidence = Confidence.INCONCLUSIVE,
                    evidence = mapOf("reason" to "build_properties_unavailable")
                )
            )
        }

        val testKeys = tags?.contains(TEST_KEYS) == true
        val debugBuild = type in DEBUG_BUILD_TYPES
        if (!testKeys && !debugBuild) return emptyList()

        return listOf(
            Signal(
                id = SignalId.ROOT_DANGEROUS_PROPS,
                category = Category.ROOT,
                confidence = Confidence.POSSIBLE,
                evidence = mapOf(
                    "tags" to (tags ?: "unknown"),
                    "buildType" to (type ?: "unknown")
                )
            )
        )
    }

    private companion object {
        const val TEST_KEYS = "test-keys"
        val DEBUG_BUILD_TYPES = setOf("userdebug", "eng")
    }
}
