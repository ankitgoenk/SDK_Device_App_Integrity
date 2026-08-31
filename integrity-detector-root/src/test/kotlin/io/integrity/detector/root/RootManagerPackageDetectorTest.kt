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

        val filtered = signals.single { it.id == SignalId.ROOT_MANAGER_PACKAGE }
        assertThat(filtered.confidence).isEqualTo(Confidence.INCONCLUSIVE)
        assertThat(filtered.evidence["reason"]).isEqualTo("package_visibility_filtered")

        // ADR-0004, INTEGRATION.md and the <queries> fragment all said the report carries
        // this. Until now none of them was true — the id did not exist and nothing emitted
        // it. The two signals answer different questions: this check could not conclude,
        // and the report as a whole was assembled without package visibility.
        val restricted = signals.single { it.id == SignalId.META_VISIBILITY_RESTRICTED }
        assertThat(restricted.confidence).isEqualTo(Confidence.INCONCLUSIVE)
        assertThat(restricted.evidence["scope"]).isEqualTo("root_manager_packages")
    }

    @Test
    fun `visibility is not reported as restricted when the probe can conclude`() = runTest {
        // The negative control: if META_VISIBILITY_RESTRICTED appeared on a device that can
        // see packages, it would be noise on every healthy Android 10 and below.
        val clean = detect(FakePackageProbe(absenceIsConclusive = true))
        val found = detect(FakePackageProbe(installed = setOf("com.rifsxd.ksunext")))

        assertThat(clean.map { it.id }).doesNotContain(SignalId.META_VISIBILITY_RESTRICTED)
        assertThat(found.map { it.id }).doesNotContain(SignalId.META_VISIBILITY_RESTRICTED)
        // And the newly queryable manager is actually detected.
        assertThat(found.single().id).isEqualTo(SignalId.ROOT_MANAGER_PACKAGE)
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
