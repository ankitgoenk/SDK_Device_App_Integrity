package io.integrity.detector.root

import com.google.common.truth.Truth.assertThat
import io.integrity.core.Confidence
import io.integrity.core.SignalId
import kotlinx.coroutines.test.runTest
import org.junit.Test

class DangerousPropertiesDetectorTest {

    private suspend fun detect(build: BuildProbe) = DangerousPropertiesDetector(build).detect(FakeDetectionContext())

    @Test
    fun `a stock release build produces no signal`() = runTest {
        assertThat(detect(FakeBuildProbe(tags = "release-keys", type = "user"))).isEmpty()
    }

    @Test
    fun `test-keys is possible, never higher`() = runTest {
        val signals = detect(FakeBuildProbe(tags = "test-keys", type = "user"))

        val signal = signals.single()
        assertThat(signal.id).isEqualTo(SignalId.ROOT_DANGEROUS_PROPS)
        assertThat(signal.confidence).isEqualTo(Confidence.POSSIBLE)
        assertThat(signal.evidence["tags"]).isEqualTo("test-keys")
    }

    @Test
    fun `a userdebug build is flagged`() = runTest {
        val signals = detect(FakeBuildProbe(tags = "release-keys", type = "userdebug"))

        assertThat(signals.single().evidence["buildType"]).isEqualTo("userdebug")
    }

    @Test
    fun `an eng build is flagged`() = runTest {
        assertThat(detect(FakeBuildProbe(tags = "release-keys", type = "eng"))).hasSize(1)
    }

    @Test
    fun `unavailable build properties are inconclusive, not clean`() = runTest {
        val signals = detect(FakeBuildProbe(tags = null, type = null))

        assertThat(signals.single().confidence).isEqualTo(Confidence.INCONCLUSIVE)
        assertThat(signals.single().evidence["reason"]).isEqualTo("build_properties_unavailable")
    }
}
