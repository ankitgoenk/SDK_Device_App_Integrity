package io.integrity.core

import com.google.common.truth.Truth.assertThat
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.test.runTest
import org.junit.Test

class DetectionEngineTest {

    private fun engine(vararg detectors: Detector) = DetectionEngine(
        detectors = detectors.toList(),
        context = FakeDetectionContext(),
        globalBudget = 10.seconds
    )

    @Test
    fun `collects signals from every applicable detector`() = runTest {
        val result = engine(
            ScriptedDetector(id = "a", signals = listOf(signal(ROOT_A, Category.ROOT))),
            ScriptedDetector(id = "b", signals = listOf(signal(ENV_A, Category.ENVIRONMENT)))
        ).run(Depth.FULL)

        assertThat(result.signals.map { it.id }).containsExactly(ROOT_A, ENV_A)
        assertThat(result.coverage).isEqualTo(1f)
    }

    @Test
    fun `detectors deeper than the requested depth are skipped`() = runTest {
        val deep = ScriptedDetector(id = "deep", minDepth = Depth.FULL, signals = listOf(signal(ROOT_A)))
        val shallow = ScriptedDetector(id = "shallow", minDepth = Depth.QUICK, signals = listOf(signal(ENV_A)))

        val result = engine(deep, shallow).run(Depth.QUICK)

        assertThat(deep.invocations).isEqualTo(0)
        assertThat(shallow.invocations).isEqualTo(1)
        assertThat(result.signals.map { it.id }).containsExactly(ENV_A)
    }

    @Test
    fun `a detector that overruns its budget degrades to an inconclusive timeout`() = runTest {
        val result = engine(
            ScriptedDetector(id = "slow", budget = 50.milliseconds, stallFor = 10.seconds)
        ).run(Depth.FULL)

        val signal = result.signals.single()
        assertThat(signal.id).isEqualTo(SignalId.META_DETECTOR_TIMEOUT)
        assertThat(signal.confidence).isEqualTo(Confidence.INCONCLUSIVE)
        assertThat(signal.evidence["detector"]).isEqualTo("slow")
    }

    @Test
    fun `a throwing detector cannot reach the host`() = runTest {
        val result = engine(
            ScriptedDetector(id = "boom", failWith = IllegalStateException("secret path /data/xyz"))
        ).run(Depth.FULL)

        val signal = result.signals.single()
        assertThat(signal.id).isEqualTo(SignalId.META_DETECTOR_ERROR)
        assertThat(signal.confidence).isEqualTo(Confidence.INCONCLUSIVE)
        assertThat(signal.evidence["exception"]).isEqualTo("IllegalStateException")
    }

    @Test
    fun `an exception message never leaks into evidence`() = runTest {
        val result = engine(
            ScriptedDetector(id = "boom", failWith = IllegalStateException("/data/user/0/secret"))
        ).run(Depth.FULL)

        assertThat(result.signals.single().evidence.values).doesNotContain("/data/user/0/secret")
    }

    @Test
    fun `one failing detector does not stop the others`() = runTest {
        val result = engine(
            ScriptedDetector(id = "boom", failWith = RuntimeException()),
            ScriptedDetector(id = "ok", signals = listOf(signal(ROOT_A, Category.ROOT)))
        ).run(Depth.FULL)

        assertThat(result.signals.map { it.id }).contains(ROOT_A)
    }

    @Test
    fun `coverage reflects the detectors that could not conclude`() = runTest {
        val result = engine(
            ScriptedDetector(id = "ok", signals = listOf(signal(ROOT_A, Category.ROOT))),
            ScriptedDetector(id = "boom", failWith = RuntimeException())
        ).run(Depth.FULL)

        assertThat(result.coverage).isEqualTo(0.5f)
    }

    @Test
    fun `a detector that ran and found nothing counts as covered`() = runTest {
        val result = engine(ScriptedDetector(id = "clean", signals = emptyList())).run(Depth.FULL)

        assertThat(result.coverage).isEqualTo(1f)
        assertThat(result.signals).isEmpty()
    }

    @Test
    fun `a detector returning only inconclusive signals is not covered`() = runTest {
        val result = engine(
            ScriptedDetector(
                id = "blind",
                signals = listOf(signal(ROOT_A, Category.ROOT, Confidence.INCONCLUSIVE))
            )
        ).run(Depth.FULL)

        assertThat(result.coverage).isEqualTo(0f)
    }

    @Test
    fun `no applicable detectors yields zero coverage rather than a clean bill of health`() = runTest {
        val result = engine().run(Depth.FULL)

        assertThat(result.coverage).isEqualTo(0f)
        assertThat(result.signals).isEmpty()
    }

    @Test
    fun `the global budget caps an over-generous detector budget`() = runTest {
        val engine = DetectionEngine(
            detectors = listOf(ScriptedDetector(id = "slow", budget = 10.seconds, stallFor = 5.seconds)),
            context = FakeDetectionContext(),
            globalBudget = 20.milliseconds
        )

        assertThat(engine.run(Depth.FULL).signals.single().id).isEqualTo(SignalId.META_DETECTOR_TIMEOUT)
    }
}
