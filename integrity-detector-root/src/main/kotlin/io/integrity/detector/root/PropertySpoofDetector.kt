package io.integrity.detector.root

import io.integrity.core.Category
import io.integrity.core.Confidence
import io.integrity.core.Depth
import io.integrity.core.DetectionContext
import io.integrity.core.Detector
import io.integrity.core.Signal
import io.integrity.core.SignalId

/**
 * `ROOT_PROP_SPOOF` — `android.os.Build` disagrees with the system property that backs it.
 *
 * **Evidence.** The names of the fields that diverged, how many pairs were comparable, and how
 * many properties were unreadable. No values: the field names carry the finding, and a build
 * fingerprint identifies a device model the backend can already infer.
 *
 * **Expected result.** `CONFIRMED` when `FINGERPRINT` diverges, `LIKELY` when only a secondary
 * field does, `INCONCLUSIVE` when nothing could be compared, and **no signal at all** when
 * everything agrees — agreement is not a clean bill of health, it is an absence of evidence.
 *
 * ### Why this comparison and not the obvious one
 *
 * The obvious design compares partitions against each other — `ro.system.build.fingerprint`
 * against `ro.build.fingerprint` — and it is catastrophically wrong. Under Project Treble the
 * system image may come from the SoC vendor while vendor and odm come from the OEM, built on
 * different days. Measured on a stock, unrooted Redmi: **26 disagreements**, including
 * `ro.product.system.manufacturer` = `QUALCOMM` against `ro.product.manufacturer` = `Xiaomi`.
 * The same survey on the rooted Pixel found **3**. That detector fires on honest phones and
 * stays quiet on compromised ones. See `docs/TESTING.md` §9.
 *
 * This comparison is different in kind. `Build.FINGERPRINT` is *initialised from*
 * `ro.build.fingerprint` in the framework, so the two agreeing is an invariant the platform
 * maintains rather than a convention vendors happen to follow. Divergence is not suspicious;
 * it is a broken invariant, and something in the process rewrote one surface without the other.
 *
 * **Known bypass.** Rewrite the property too. Nothing prevents it — it is simply more work and
 * more breakage, which is exactly why the spoofers in the wild do not bother: Play Integrity
 * Fork rewrites `Build` fields for `com.google.android.gms.unstable` and leaves
 * `ro.build.fingerprint` untouched. A hook on `SystemProperties.get` defeats this outright, as
 * does one on this detector. It catches a *lazy, prevalent* technique, not a determined one.
 *
 * **False positives.** None observed. An unreadable property is excluded from the comparison
 * rather than counted as a difference — the trap that sank the partition design. `FINGERPRINT`
 * is decisive because the framework assigns it directly; the secondary fields are only `LIKELY`
 * because Android resolves some `ro.product.*` reads through a partition fallback chain, and
 * that has been measured on two devices, which is not enough to call it guaranteed.
 */
internal class PropertySpoofDetector(
    private val fields: BuildFieldProbe = RealBuildFieldProbe,
    private val properties: SystemPropertyProbe = RealSystemPropertyProbe
) : Detector {

    override val id: String = "root.prop-spoof"
    override val category: Category = Category.ROOT
    override val minDepth: Depth = Depth.STANDARD

    override suspend fun detect(context: DetectionContext): List<Signal> {
        val diverged = mutableListOf<String>()
        var comparable = 0
        var unreadable = 0

        for ((field, property) in PAIRS) {
            val fieldValue = fields.field(field)
            val propertyValue = properties.get(property)
            if (fieldValue.isNullOrEmpty() || propertyValue.isNullOrEmpty()) {
                unreadable++
                continue
            }
            comparable++
            if (fieldValue != propertyValue) diverged += field
        }

        if (comparable == 0) {
            return listOf(
                signal(
                    Confidence.INCONCLUSIVE,
                    mapOf("reason" to "nothing_comparable", "unreadable" to unreadable.toString())
                )
            )
        }

        if (diverged.isEmpty()) return emptyList()

        return listOf(
            signal(
                if (DECISIVE_FIELD in diverged) Confidence.CONFIRMED else Confidence.LIKELY,
                mapOf(
                    "diverged" to diverged.joinToString(","),
                    "comparable" to comparable.toString(),
                    "unreadable" to unreadable.toString()
                )
            )
        )
    }

    private fun signal(confidence: Confidence, evidence: Map<String, String>) = Signal(
        id = SignalId.ROOT_PROP_SPOOF,
        category = Category.ROOT,
        confidence = confidence,
        evidence = evidence
    )

    private companion object {
        /**
         * Assigned directly from `ro.build.fingerprint` by the framework, so a mismatch here is
         * unambiguous. The rest can in principle be resolved through a partition fallback chain.
         */
        const val DECISIVE_FIELD = "FINGERPRINT"

        val PAIRS = listOf(
            "FINGERPRINT" to "ro.build.fingerprint",
            "MODEL" to "ro.product.model",
            "DEVICE" to "ro.product.device",
            "PRODUCT" to "ro.product.name",
            "BRAND" to "ro.product.brand",
            "MANUFACTURER" to "ro.product.manufacturer",
            "TAGS" to "ro.build.tags",
            "TYPE" to "ro.build.type"
        )
    }
}
