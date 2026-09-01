package io.integrity.detector.hooking

import com.google.common.truth.Truth.assertThat
import io.integrity.core.Confidence
import io.integrity.core.DetectionContext
import io.integrity.core.IntegrityConfig
import io.integrity.core.SignalId
import kotlinx.coroutines.test.runTest
import org.junit.Test

/**
 * The decision table for `HOOK_UNEXPECTED_MODULE`.
 *
 * **Every fixture line below is verbatim from a real device**, captured on 2026-09-01 and
 * recorded in `docs/TESTING.md` §9. That is not decoration. Three of the cases here are ones
 * invented fixtures would have got wrong: ART's boot image is executable and lives under
 * `/data/misc`, resource overlays sit outside every allow-listed prefix but are not executable,
 * and one anonymous region carries a *path inside its name*. Each of those was a false positive
 * in an earlier form of this rule.
 */
class UnexpectedModuleDetectorTest {

    private object NoContext : DetectionContext {
        override val appContext get() = error("not needed: the probe is injected")
        override val config: IntegrityConfig = IntegrityConfig.Builder().build()
    }

    private class Fake(private val lines: List<String>?) : MapsProbe {
        override fun lines(): List<String>? = lines
    }

    private suspend fun detect(vararg lines: String) = UnexpectedModuleDetector(Fake(lines.toList())).detect(NoContext)

    // --- verbatim device captures ------------------------------------------------------

    private val systemLib =
        "756a455000-756a5c0000 r-xp 00000000 fe:37 61 " +
            "/apex/com.android.tethering/lib64/libmainlinecronet.141.0.7340.3.so"

    /** The app's own code, mapped straight out of the APK rather than an extracted lib dir. */
    private val ownApk =
        "75af111000-75af114000 r-xp 00940000 fe:3a 41248 " +
            "/data/app/~~BII7aZrta_oi8wW_WDyPYQ==/io.integrity.sample-FPeXLHWWMce_g8tgWlQOQA==/base.apk"

    /** Executable, outside every other allow-listed prefix, and completely legitimate. */
    private val bootImage =
        "71ab0000-725db000 r-xp 0030c000 fd:29 1927330 " +
            "/data/misc/apexdata/com.android.art/dalvik-cache/arm64/boot.oat"

    /** Outside every allow-listed prefix, but not executable. */
    private val resourceOverlay =
        "7877b91000-7877b93000 r--s 00000000 fe:3a 10600 " +
            "/data/resource-cache/data@resource-cache@com.android.systemui-dynamic-YzbO.frro@idmap"

    /** Anonymous — and its *name contains a path*. */
    private val anonHeap =
        "703e4000-717a4000 rw-p 00000000 00:00 0 " +
            "[anon:dalvik-/data/misc/apexdata/com.android.art/dalvik-cache/boot.art]"

    private val anonNoPath = "750e00b000-750e304000 ---p 00000000 00:00 0 "

    /**
     * ART's JIT code cache. Executable, its name starts with a slash, and it sits under no
     * allow-listable prefix — present on **every** device measured, hooked or clean.
     */
    private val jitCache = "7b0e400000-7b0e500000 r-xp 00000000 00:04 12345 /memfd:jit-cache (deleted)"
    private val jitZygoteCache =
        "7b0f400000-7b0f500000 r-xp 00000000 00:04 12346 /memfd:jit-zygote-cache (deleted)"

    /** The positive control: Vector's Zygisk library, resident in a hooked process. */
    private val hookLib =
        "7f1da53000-7f1db7b000 r-xp 00000000 fe:3a 42226 " +
            "/data/adb/modules/zygisk_vector/zygisk/arm64-v8a.so"

    private val hookLibSecondSegment =
        "7f1db89000-7f1db8b000 r-xp 0012e000 fe:3a 42226 " +
            "/data/adb/modules/zygisk_vector/zygisk/arm64-v8a.so"

    // --- the decision table -------------------------------------------------------------

    @Test
    fun `a clean process produces no signal`() = runTest {
        val signals = detect(
            systemLib,
            ownApk,
            bootImage,
            resourceOverlay,
            anonHeap,
            anonNoPath,
            jitCache,
            jitZygoteCache
        )

        assertThat(signals).isEmpty()
    }

    @Test
    fun `the JIT cache is anonymous memory with a path-shaped name, and must not fire`() = runTest {
        // memfd_create names anonymous memory. ART uses it for the JIT, so these two mappings
        // exist on every Android device running managed code — executable, leading slash, under
        // no allow-listable prefix. An earlier form of this rule flagged both.
        //
        // The first measurement missed them for an unrelated reason: the extracting script took
        // the last whitespace-separated field as the path, which for these lines is "(deleted)".
        // It reported the right answer by accident. This test is the reason it cannot recur.
        assertThat(detect(jitCache, jitZygoteCache)).isEmpty()
    }

    @Test
    fun `a real library unlinked after loading is still file-backed`() = runTest {
        // " (deleted)" on a genuine path is not the memfd case: a library unlinked after being
        // mapped is classic anti-forensics and worth reporting. No reference capture contains
        // one, so this is the only place the behaviour is pinned.
        val unlinked = "70000000-70001000 r-xp 00000000 fd:01 999 /data/local/tmp/agent.so (deleted)"

        assertThat(detect(unlinked).single().confidence).isEqualTo(Confidence.CONFIRMED)
    }

    @Test
    fun `a resident hook is CONFIRMED and names the root module directory`() = runTest {
        // The positive control, reproduced from the on-device measurement.
        val signals = detect(systemLib, ownApk, hookLib)

        assertThat(signals).hasSize(1)
        assertThat(signals[0].id).isEqualTo(SignalId.HOOK_UNEXPECTED_MODULE)
        assertThat(signals[0].confidence).isEqualTo(Confidence.CONFIRMED)
        assertThat(signals[0].evidence["count"]).isEqualTo("1")
        assertThat(signals[0].evidence["rootModuleDir"]).isEqualTo("true")
    }

    @Test
    fun `several segments of one library count once`() = runTest {
        // A loaded .so maps three times. Counting segments would inflate the evidence and
        // make "count" mean something other than "how many unexpected libraries".
        val signals = detect(hookLib, hookLibSecondSegment)

        assertThat(signals[0].evidence["count"]).isEqualTo("1")
    }

    @Test
    fun `an unrecognised prefix is only LIKELY`() = runTest {
        // Could be an OEM mapping its own library. Only /data/adb and /data/local/tmp are
        // places nothing legitimate loads from.
        val oemLib = "70000000-70001000 r-xp 00000000 fd:01 999 /oem/lib64/libcarrier.so"

        val signals = detect(systemLib, oemLib)

        assertThat(signals[0].confidence).isEqualTo(Confidence.LIKELY)
        assertThat(signals[0].evidence["rootModuleDir"]).isEqualTo("false")
    }

    @Test
    fun `a staged agent under data local tmp is CONFIRMED`() = runTest {
        val agent = "70000000-70001000 r-xp 00000000 fd:01 999 /data/local/tmp/re.frida.server/agent.so"

        assertThat(detect(agent)[0].confidence).isEqualTo(Confidence.CONFIRMED)
    }

    @Test
    fun `evidence carries digests, never paths`() = runTest {
        // Hard rule 3: a mapping under /data/data/<package>/ would otherwise ship the name of
        // an installed application. Nothing in the evidence may be reversible to a path.
        val thirdParty = "70000000-70001000 r-xp 00000000 fd:01 9 /data/data/com.example.secret/lib/x.so"

        val evidence = detect(thirdParty).single().evidence

        assertThat(evidence.values.joinToString()).doesNotContain("com.example.secret")
        assertThat(evidence.values.joinToString()).doesNotContain("/data/data")
        assertThat(evidence["digests"]).matches("[0-9a-f]{16}")
    }

    @Test
    fun `an unreadable map is INCONCLUSIVE, not clean`() = runTest {
        val signals = UnexpectedModuleDetector(Fake(null)).detect(NoContext)

        assertThat(signals).hasSize(1)
        assertThat(signals[0].confidence).isEqualTo(Confidence.INCONCLUSIVE)
        assertThat(signals[0].evidence["reason"]).isEqualTo("maps_unreadable")
    }

    @Test
    fun `an anonymous region whose name contains a path is not a mapping`() = runTest {
        // [anon:dalvik-/data/misc/...] is a name, not a file. A parser that took the last
        // whitespace-separated field as a path and did not check for a leading slash would
        // treat this as an unexpected module on every Android device in existence.
        assertThat(detect(anonHeap)).isEmpty()
        assertThat(detect(anonNoPath)).isEmpty()
    }

    @Test
    fun `the boot image is executable, outside the obvious prefixes, and must not fire`() = runTest {
        // Present on the Xiaomi, absent on the Pixel. A rule validated on one device would
        // fire on every phone with a separately-compiled boot image.
        assertThat(detect(bootImage)).isEmpty()
    }

    @Test
    fun `a non-executable file outside the allow-list must not fire`() = runTest {
        // /data/resource-cache is in no allow-list. Requiring executability is what removes
        // it, and 112 other unexplained paths with it, without enumerating any of them.
        assertThat(detect(resourceOverlay)).isEmpty()
    }
}
