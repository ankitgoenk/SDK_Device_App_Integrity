package io.integrity.detector.root

import com.google.common.truth.Truth.assertThat
import io.integrity.core.Confidence
import io.integrity.core.IntegrityConfig
import io.integrity.core.SignalId
import kotlinx.coroutines.test.runTest
import org.junit.Test

class RootManagerPackageDetectorTest {

    private suspend fun detect(probe: PackageProbe, config: IntegrityConfig = IntegrityConfig.Builder().build()) =
        RootManagerPackageDetector(probe).detect(FakeDetectionContext(config))

    @Test
    fun `an installed manager is likely rather than confirmed`() = runTest {
        val signals = detect(FakePackageProbe(installed = setOf("com.topjohnwu.magisk")))

        val signal = signals.single()
        assertThat(signal.id).isEqualTo(SignalId.ROOT_MANAGER_PACKAGE)
        assertThat(signal.confidence).isEqualTo(Confidence.LIKELY)
        assertThat(signal.evidence["count"]).isEqualTo("1")
    }

    @Test
    fun `package names are hashed before they can leave the device`() = runTest {
        val signals = detect(FakePackageProbe(installed = setOf("com.topjohnwu.magisk")))

        val packages = signals.single().evidence.getValue("packages")
        assertThat(packages).doesNotContain("magisk")
        assertThat(packages).hasLength(16)
        assertThat(packages).isEqualTo(hashPackageName("com.topjohnwu.magisk"))
    }

    @Test
    fun `nothing installed on a device where absence is meaningful is a clean result`() = runTest {
        val signals = detect(FakePackageProbe(absenceIsConclusive = true))

        assertThat(signals).isEmpty()
    }

    @Test
    fun `nothing visible under package filtering is inconclusive, never clean`() = runTest {
        val signals = detect(FakePackageProbe(absenceIsConclusive = false))

        val signal = signals.single()
        assertThat(signal.confidence).isEqualTo(Confidence.INCONCLUSIVE)
        assertThat(signal.evidence["reason"]).isEqualTo("package_visibility_filtered")
    }

    @Test
    fun `a host allowlisted package is ignored`() = runTest {
        val config = IntegrityConfig.Builder()
            .allowlistPackages("com.topjohnwu.magisk")
            .build()

        val signals = detect(FakePackageProbe(installed = setOf("com.topjohnwu.magisk")), config)

        assertThat(signals).isEmpty()
    }

    @Test
    fun `several managers are reported together`() = runTest {
        val signals = detect(
            FakePackageProbe(installed = setOf("com.topjohnwu.magisk", "eu.chainfire.supersu"))
        )

        assertThat(signals.single().evidence["count"]).isEqualTo("2")
    }
}
