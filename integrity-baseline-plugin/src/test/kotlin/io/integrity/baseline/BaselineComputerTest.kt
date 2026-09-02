package io.integrity.baseline

import com.google.common.truth.Truth.assertThat
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * The digesting, which is the part that can be wrong.
 *
 * Gradle-free on purpose: a test that needs an Android project to run is a test nobody runs,
 * and this logic is what decides whether a tampered build is noticed.
 */
class BaselineComputerTest {

    @get:Rule
    val temp = TemporaryFolder()

    private fun archive(vararg entries: Pair<String, String>): File {
        val file = temp.newFile("artifact-${entries.hashCode()}.apk")
        ZipOutputStream(file.outputStream()).use { zip ->
            entries.forEach { (name, content) ->
                zip.putNextEntry(ZipEntry(name))
                zip.write(content.toByteArray())
                zip.closeEntry()
            }
        }
        return file
    }

    private fun sample(dex2: String = "second") = archive(
        "classes.dex" to "first",
        "classes2.dex" to dex2,
        "lib/arm64-v8a/libintegrity.so" to "native",
        "res/layout/main.xml" to "irrelevant",
        "resources.arsc" to "irrelevant",
        "AndroidManifest.xml" to "irrelevant"
    )

    @Test
    fun `digests every dex and native library and nothing else`() {
        val baseline = BaselineComputer.compute(sample(), "io.integrity.sample")

        assertThat(baseline.dex.keys).containsExactly("classes.dex", "classes2.dex")
        assertThat(baseline.nativeLibs.keys).containsExactly("lib/arm64-v8a/libintegrity.so")
        assertThat(baseline.packageName).isEqualTo("io.integrity.sample")
        // Resources and the manifest are deliberately absent: APP_RESOURCE_TAMPER is a
        // separate signal with a separate list, and folding them in here would make one
        // digest answer two questions.
        //
        // Named rather than implied, because DETECTION_TRIAGE.md asserted the opposite —
        // "integrity-baseline-plugin already digests resources.arsc and the res/ tree" — and
        // moved APP_RESOURCE_TAMPER to BUILD on the strength of it. `containsExactly` above
        // already pins this; this line is here so the sentence is falsifiable at a glance.
        assertThat(baseline.dex.keys + baseline.nativeLibs.keys)
            .containsNoneOf("AndroidManifest.xml", "resources.arsc", "res/layout/main.xml")
    }

    @Test
    fun `digests are sha-256 of the entry contents`() {
        val baseline = BaselineComputer.compute(sample(), "p")

        // Computed outside this codebase: `echo -n first | shasum -a 256`. An assertion that
        // recomputed it with the same code would agree with itself and prove nothing.
        assertThat(baseline.dex["classes.dex"])
            .isEqualTo("a7937b64b8caa58f03721bb6bacf5c78cb235febe0e70b1b84cd99541461a08e")
    }

    // --- the positive control ------------------------------------------------------------

    @Test
    fun `a tampered dex changes the baseline`() {
        // Without this the test above proves only that the function returns strings. The
        // whole point of a baseline is that it differs when the artifact differs.
        val clean = BaselineComputer.compute(sample(), "p")
        val tampered = BaselineComputer.compute(sample(dex2 = "second, but patched"), "p")

        assertThat(tampered.dex["classes2.dex"]).isNotEqualTo(clean.dex["classes2.dex"])
        // And only the changed entry moves — a digest that changed everything would hide
        // which part was touched.
        assertThat(tampered.dex["classes.dex"]).isEqualTo(clean.dex["classes.dex"])
        assertThat(tampered.nativeLibs).isEqualTo(clean.nativeLibs)
        assertThat(tampered.toJson()).isNotEqualTo(clean.toJson())
    }

    @Test
    fun `the same artifact digests identically twice`() {
        // Zip entry order is not a contract and this file is diffed across builds.
        val a = BaselineComputer.compute(sample(), "p").toJson()
        val b = BaselineComputer.compute(sample(), "p").toJson()

        assertThat(a).isEqualTo(b)
    }

    @Test
    fun `entry order in the archive does not change the output`() {
        val forward = archive(
            "classes.dex" to "first",
            "classes2.dex" to "second",
            "lib/arm64-v8a/libintegrity.so" to "native"
        )
        val reversed = archive(
            "lib/arm64-v8a/libintegrity.so" to "native",
            "classes2.dex" to "second",
            "classes.dex" to "first"
        )

        assertThat(BaselineComputer.compute(forward, "p").toJson())
            .isEqualTo(BaselineComputer.compute(reversed, "p").toJson())
    }

    @Test
    fun `an artifact with no dex produces an empty dex map`() {
        // The task turns this into a build failure; the computer reports it truthfully rather
        // than inventing an entry.
        val baseline = BaselineComputer.compute(archive("res/x" to "y"), "p")

        assertThat(baseline.dex).isEmpty()
    }

    @Test
    fun `canonical json is sorted and stable`() {
        val json = Baseline(
            packageName = "p",
            dex = linkedMapOf("classes2.dex" to "bb", "classes.dex" to "aa"),
            nativeLibs = emptyMap()
        ).toJson()

        // Keys lexicographically sorted, and the aggregate is the shared DexAggregate value —
        // the same construction the client runs, so build and device cannot disagree.
        val aggregate = io.integrity.core.DexAggregate.of(mapOf("classes.dex" to "aa", "classes2.dex" to "bb"))
        assertThat(json).isEqualTo(
            """{"dex":{"classes.dex":"aa","classes2.dex":"bb"},""" +
                """"dexAggregate":"$aggregate","nativeLibs":{},"packageName":"p"}"""
        )
    }
}
