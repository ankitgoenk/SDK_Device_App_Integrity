package io.integrity.detector.root

import com.google.common.truth.Truth.assertThat
import io.integrity.core.Category
import io.integrity.core.Confidence
import io.integrity.core.SignalId
import kotlinx.coroutines.test.runTest
import org.junit.Test

class SuBinaryDetectorTest {

    private suspend fun detect(files: FileProbe) = SuBinaryDetector(files).detect(FakeDetectionContext())

    @Test
    fun `a clean device produces no signal`() = runTest {
        assertThat(detect(CLEAN_FILES)).isEmpty()
    }

    @Test
    fun `an su binary is confirmed`() = runTest {
        val signals = detect(FakeFileProbe(setOf("/system/xbin/su")))

        val signal = signals.single()
        assertThat(signal.id).isEqualTo(SignalId.ROOT_SU_BINARY)
        assertThat(signal.category).isEqualTo(Category.ROOT)
        assertThat(signal.confidence).isEqualTo(Confidence.CONFIRMED)
        assertThat(signal.evidence["artefact"]).isEqualTo("su")
    }

    @Test
    fun `a magisk binary is confirmed`() = runTest {
        val signals = detect(FakeFileProbe(setOf("/system/bin/magiskpolicy")))

        assertThat(signals.single().confidence).isEqualTo(Confidence.CONFIRMED)
        assertThat(signals.single().evidence["artefact"]).isEqualTo("magisk")
    }

    @Test
    fun `busybox alone is only possible because stock ROMs ship it`() = runTest {
        val signals = detect(FakeFileProbe(setOf("/system/xbin/busybox")))

        assertThat(signals.single().confidence).isEqualTo(Confidence.POSSIBLE)
    }

    @Test
    fun `busybox alongside su is still confirmed`() = runTest {
        val signals = detect(FakeFileProbe(setOf("/system/xbin/busybox", "/system/bin/su")))

        assertThat(signals.single().confidence).isEqualTo(Confidence.CONFIRMED)
        assertThat(signals.single().evidence["matches"]).isEqualTo("2")
    }

    @Test
    fun `every known su location is probed`() = runTest {
        val locations = listOf(
            "/system/bin/su",
            "/system/xbin/su",
            "/system/sbin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/system/usr/we-need-root/su",
            "/vendor/bin/su",
            "/product/bin/su"
        )

        locations.forEach { path ->
            assertThat(detect(FakeFileProbe(setOf(path)))).hasSize(1)
        }
    }

    @Test
    fun `evidence never contains a filesystem path`() = runTest {
        val signals = detect(FakeFileProbe(setOf("/system/xbin/su")))

        assertThat(signals.single().evidence.values.none { it.contains("/") }).isTrue()
    }

    @Test
    fun `a probe that cannot stat anything reports nothing rather than guessing`() = runTest {
        val throwing = object : FileProbe {
            override fun exists(path: String): Boolean = false
        }

        assertThat(detect(throwing)).isEmpty()
    }
}
