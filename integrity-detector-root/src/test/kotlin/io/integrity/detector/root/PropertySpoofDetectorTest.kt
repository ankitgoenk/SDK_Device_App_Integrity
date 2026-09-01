package io.integrity.detector.root

import com.google.common.truth.Truth.assertThat
import io.integrity.core.Confidence
import io.integrity.core.DetectionContext
import io.integrity.core.IntegrityConfig
import io.integrity.core.SignalId
import kotlinx.coroutines.test.runTest
import org.junit.Test

/**
 * The decision table for `ROOT_PROP_SPOOF`.
 *
 * The fixtures are the real readings from `docs/TESTING.md` §9 rather than invented strings,
 * because two of the cases below are ones an invented fixture would have got wrong: the
 * Treble-mismatched clean device, and the property that reads empty to an app.
 */
class PropertySpoofDetectorTest {

    private object NoContext : DetectionContext {
        override val appContext get() = error("not needed: both probes are injected")
        override val config: IntegrityConfig = IntegrityConfig.Builder().build()
    }

    private class Fields(private val values: Map<String, String?>) : BuildFieldProbe {
        override fun field(name: String): String? = values[name]
    }

    private class Props(private val values: Map<String, String?>) : SystemPropertyProbe {
        override fun get(name: String): String? = values[name]
    }

    /** The measured Pixel 10a reading: every pair agrees. */
    private val honest = mapOf(
        "FINGERPRINT" to "google/stallion/stallion:16/CP1A.260505.005/15081906:user/release-keys",
        "MODEL" to "Pixel 10a",
        "DEVICE" to "stallion",
        "PRODUCT" to "stallion",
        "BRAND" to "google",
        "MANUFACTURER" to "Google",
        "TAGS" to "release-keys",
        "TYPE" to "user"
    )
    private val honestProps = mapOf(
        "ro.build.fingerprint" to honest["FINGERPRINT"],
        "ro.product.model" to "Pixel 10a",
        "ro.product.device" to "stallion",
        "ro.product.name" to "stallion",
        "ro.product.brand" to "google",
        "ro.product.manufacturer" to "Google",
        "ro.build.tags" to "release-keys",
        "ro.build.type" to "user"
    )

    private suspend fun detect(f: Map<String, String?>, p: Map<String, String?>) =
        PropertySpoofDetector(Fields(f), Props(p)).detect(NoContext)

    @Test
    fun `an honest device produces no signal`() = runTest {
        assertThat(detect(honest, honestProps)).isEmpty()
    }

    @Test
    fun `a spoofed fingerprint is CONFIRMED`() = runTest {
        // The positive control, reproduced from the on-device measurement: an Xposed module
        // rewrote Build.FINGERPRINT to a Pixel 8 Pro and left ro.build.fingerprint alone.
        val spoofed = honest + mapOf(
            "FINGERPRINT" to "google/husky/husky:14/AP1A.240405.002/11480754:user/release-keys",
            "MODEL" to "Pixel 8 Pro",
            "DEVICE" to "husky"
        )

        val signals = detect(spoofed, honestProps)

        assertThat(signals).hasSize(1)
        assertThat(signals[0].id).isEqualTo(SignalId.ROOT_PROP_SPOOF)
        assertThat(signals[0].confidence).isEqualTo(Confidence.CONFIRMED)
        assertThat(signals[0].evidence["diverged"]).isEqualTo("FINGERPRINT,MODEL,DEVICE")
    }

    @Test
    fun `a secondary field alone is only LIKELY`() = runTest {
        // Android resolves some ro.product.* reads through a partition fallback chain, and
        // that has been measured on two devices — not enough to call a mismatch decisive.
        val signals = detect(honest + mapOf("MODEL" to "Pixel 8 Pro"), honestProps)

        assertThat(signals[0].confidence).isEqualTo(Confidence.LIKELY)
        assertThat(signals[0].evidence["diverged"]).isEqualTo("MODEL")
    }

    @Test
    fun `an unreadable property is excluded, never counted as a difference`() = runTest {
        // The trap that sank the partition design: ro.bootimage.build.fingerprint returns its
        // value to adb shell and an EMPTY STRING to an app. Scoring empty as "different" fires
        // on a clean device. This test is the reason the detector cannot regress into that.
        val blinded = honestProps + mapOf("ro.build.fingerprint" to "", "ro.product.model" to null)

        val signals = detect(honest, blinded)

        assertThat(signals).isEmpty()
    }

    @Test
    fun `nothing comparable is INCONCLUSIVE, not clean`() = runTest {
        val signals = detect(honest, emptyMap())

        assertThat(signals).hasSize(1)
        assertThat(signals[0].confidence).isEqualTo(Confidence.INCONCLUSIVE)
        assertThat(signals[0].evidence["reason"]).isEqualTo("nothing_comparable")
        assertThat(signals[0].evidence["unreadable"]).isEqualTo("8")
    }

    @Test
    fun `a Treble partition mismatch is not this detector's business`() = runTest {
        // Measured on a stock, unrooted Redmi: ro.system.build.fingerprint says
        // "qti/missi/missi", ro.product.system.manufacturer says QUALCOMM. Twenty-six
        // disagreements between partitions, on an honest phone. None of them involve the
        // Build-versus-its-own-property relationship, so this detector stays silent — which
        // is the entire reason it compares what it compares.
        val redmiFields = mapOf(
            "FINGERPRINT" to "Redmi/sweetinpro/sweetin:13/TKQ1.221013.002/V14.0.1.0.TKFINXM:user/release-keys",
            "MODEL" to "M2101K6I",
            "DEVICE" to "sweetin",
            "PRODUCT" to "sweetinpro",
            "BRAND" to "Redmi",
            "MANUFACTURER" to "Xiaomi",
            "TAGS" to "release-keys",
            "TYPE" to "user"
        )
        val redmiProps = mapOf(
            "ro.build.fingerprint" to redmiFields["FINGERPRINT"],
            "ro.product.model" to "M2101K6I",
            "ro.product.device" to "sweetin",
            "ro.product.name" to "sweetinpro",
            "ro.product.brand" to "Redmi",
            "ro.product.manufacturer" to "Xiaomi",
            "ro.build.tags" to "release-keys",
            "ro.build.type" to "user"
        )

        assertThat(detect(redmiFields, redmiProps)).isEmpty()
    }
}
