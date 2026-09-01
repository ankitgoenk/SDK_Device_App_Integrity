package io.integrity.detector.app

import com.google.common.truth.Truth.assertThat
import io.integrity.core.Confidence
import io.integrity.core.DetectionContext
import io.integrity.core.IntegrityConfig
import io.integrity.core.SignalId
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlinx.coroutines.test.runTest
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * The decision table for `APP_DEX_DIGEST_MISMATCH`, and the measurement underneath it.
 *
 * The measurement is exercised against real zip archives rather than a stubbed digest, because
 * "we digested the right entries in a stable order" is the part that can silently be wrong —
 * and because the aggregate must match what `integrity-baseline-plugin` computes for the same
 * bytes, which a mocked digest could never demonstrate.
 */
class DexDigestDetectorTest {

    @get:Rule
    val temp = TemporaryFolder()

    private object NoContextConfig {
        fun with(digest: String?) = object : DetectionContext {
            override val appContext get() = error("not needed: the probe is injected")
            override val config: IntegrityConfig = IntegrityConfig.Builder()
                .apply { if (digest != null) expectedDexDigest(digest) }
                .build()
        }
    }

    private class FakeProbe(private val path: String?, private val splits: Int = 0) : ApkDexProbe {
        override fun baseApkPath(): String? = path
        override fun splitCount(): Int = splits
    }

    private fun apk(name: String, vararg entries: Pair<String, String>): File {
        val file = temp.newFile(name)
        ZipOutputStream(file.outputStream()).use { zip ->
            entries.forEach { (entryName, content) ->
                zip.putNextEntry(ZipEntry(entryName))
                zip.write(content.toByteArray())
                zip.closeEntry()
            }
        }
        return file
    }

    private fun cleanApk(name: String = "clean.apk", dex2: String = "second") = apk(
        name,
        "classes.dex" to "first",
        "classes2.dex" to dex2,
        "res/layout/main.xml" to "irrelevant"
    )

    private suspend fun detect(probe: ApkDexProbe, expected: String? = null) =
        DexDigestDetector(probe).detect(NoContextConfig.with(expected))

    private fun digestOf(file: File) = ApkDexMeasurement.of(file.absolutePath)!!.digest

    // --- the decision table ---------------------------------------------------------------

    @Test
    fun `a matching baseline produces no signal`() = runTest {
        val file = cleanApk()

        val signals = detect(FakeProbe(file.absolutePath), digestOf(file))

        assertThat(signals).isEmpty()
    }

    @Test
    fun `a tampered dex is CONFIRMED, which escalates decisively`() = runTest {
        // The positive control. APP_DEX_DIGEST_MISMATCH is in RiskScorer.DECISIVE_SIGNALS, so
        // a CONFIRMED instance produces COMPROMISED on its own — this assertion is the reason
        // that is safe to allow.
        val baseline = digestOf(cleanApk("baseline.apk"))
        val tampered = cleanApk("tampered.apk", dex2 = "second, but patched")

        val signals = detect(FakeProbe(tampered.absolutePath), baseline)

        assertThat(signals).hasSize(1)
        assertThat(signals[0].id).isEqualTo(SignalId.APP_DEX_DIGEST_MISMATCH)
        assertThat(signals[0].confidence).isEqualTo(Confidence.CONFIRMED)
        assertThat(signals[0].evidence["dexCount"]).isEqualTo("2")
    }

    @Test
    fun `no baseline reports the measurement instead of a verdict`() = runTest {
        // The ordinary state of an integration that has not adopted the plugin. The digest
        // still travels, so a backend holding the baseline can do what this client cannot.
        val file = cleanApk()

        val signals = detect(FakeProbe(file.absolutePath), expected = null)

        assertThat(signals).hasSize(1)
        assertThat(signals[0].confidence).isEqualTo(Confidence.INCONCLUSIVE)
        assertThat(signals[0].evidence["reason"]).isEqualTo("no_baseline_configured")
        assertThat(signals[0].evidence["dexDigest"]).matches("[0-9a-f]{64}")
        assertThat(signals[0].evidence["dexCount"]).isEqualTo("2")
    }

    @Test
    fun `a split install declines rather than accusing`() = runTest {
        // The baseline covers the base APK only. Comparing part of an app against a whole one
        // would make Play Feature Delivery look like tampering — and this signal escalates.
        val file = cleanApk()

        val signals = detect(FakeProbe(file.absolutePath, splits = 2), expected = "whatever")

        assertThat(signals[0].confidence).isEqualTo(Confidence.INCONCLUSIVE)
        assertThat(signals[0].evidence["reason"]).isEqualTo("split_apks_present")
        assertThat(signals[0].evidence["splits"]).isEqualTo("2")
    }

    @Test
    fun `every unmeasurable outcome is inconclusive with a distinct reason`() = runTest {
        val missing = detect(FakeProbe(null), "x").single()
        val unreadable = detect(FakeProbe(temp.newFile("not-a-zip.apk").absolutePath), "x").single()

        assertThat(missing.evidence["reason"]).isEqualTo("apk_path_unavailable")
        assertThat(unreadable.evidence["reason"]).isEqualTo("apk_unreadable")
        assertThat(missing.confidence).isEqualTo(Confidence.INCONCLUSIVE)
        assertThat(unreadable.confidence).isEqualTo(Confidence.INCONCLUSIVE)
    }

    @Test
    fun `an apk with no dex is unreadable rather than a match`() = runTest {
        // Zero entries must never aggregate to a stable digest that could accidentally equal
        // a baseline, and must never read as "nothing wrong".
        val file = apk("nodex.apk", "res/x" to "y")

        val signals = detect(FakeProbe(file.absolutePath), "x")

        assertThat(signals.single().evidence["reason"]).isEqualTo("apk_unreadable")
    }

    // --- the measurement ------------------------------------------------------------------

    @Test
    fun `the aggregate ignores everything that is not dex`() = runTest {
        val withExtras = apk(
            "extras.apk",
            "classes.dex" to "first",
            "classes2.dex" to "second",
            "res/layout/main.xml" to "changed",
            "lib/arm64-v8a/libfoo.so" to "changed"
        )
        val bare = apk("bare.apk", "classes.dex" to "first", "classes2.dex" to "second")

        assertThat(digestOf(withExtras)).isEqualTo(digestOf(bare))
    }

    @Test
    fun `the aggregate is independent of entry order`() = runTest {
        val forward = apk("f.apk", "classes.dex" to "a", "classes2.dex" to "b")
        val reversed = apk("r.apk", "classes2.dex" to "b", "classes.dex" to "a")

        assertThat(digestOf(forward)).isEqualTo(digestOf(reversed))
    }

    @Test
    fun `entry names cannot be framed to collide`() = runTest {
        // The aggregate joins "name:digest" with newlines. A name carrying a delimiter must
        // not be able to impersonate two entries.
        val a = apk("a.apk", "classes.dex" to "x")
        val b = apk("b.apk", "classes.dex" to "x", "classes2.dex" to "")

        assertThat(digestOf(a)).isNotEqualTo(digestOf(b))
    }
}
