package io.integrity.core

import com.google.common.truth.Truth.assertThat
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.test.runTest
import org.junit.Test

/**
 * Diagnostics describe what ran. The tests that matter are the ones pinning what they must
 * **not** do: reach the report, reach the wire, or turn "found nothing" into a clean bill.
 */
class DiagnosticsTest {

    private fun engine(vararg detectors: Detector, budget: kotlin.time.Duration = 5.seconds) =
        DetectionEngine(detectors.toList(), FakeDetectionContext(), budget)

    private val evidence = Signal(
        id = SignalId.ROOT_SU_BINARY,
        category = Category.ROOT,
        confidence = Confidence.CONFIRMED,
        evidence = mapOf("artefact" to "su")
    )
    private val inconclusive = Signal(
        id = SignalId.ROOT_MANAGER_PACKAGE,
        category = Category.ROOT,
        confidence = Confidence.INCONCLUSIVE,
        evidence = mapOf("reason" to "package_visibility_filtered")
    )

    @Test
    fun `each detector's outcome is classified`() = runTest {
        val result = engine(
            ScriptedDetector(id = "found-nothing"),
            ScriptedDetector(id = "has-evidence", signals = listOf(evidence)),
            ScriptedDetector(id = "cannot-tell", signals = listOf(inconclusive)),
            ScriptedDetector(id = "throws", failWith = IllegalStateException("boom"))
        ).run(Depth.FULL)

        val byId = result.runs.associateBy { it.detectorId }
        assertThat(byId.getValue("found-nothing").outcome).isEqualTo(RunOutcome.FOUND_NOTHING)
        assertThat(byId.getValue("has-evidence").outcome).isEqualTo(RunOutcome.EMITTED_EVIDENCE)
        assertThat(byId.getValue("cannot-tell").outcome).isEqualTo(RunOutcome.INCONCLUSIVE)
        assertThat(byId.getValue("throws").outcome).isEqualTo(RunOutcome.FAILED)
    }

    @Test
    fun `a detector skipped for depth is reported as skipped, not as clean`() = runTest {
        // The distinction the whole surface exists to make. A FULL-only detector that never ran
        // at QUICK depth must not read as "checked and found nothing".
        val result = engine(
            ScriptedDetector(id = "quick", minDepth = Depth.QUICK),
            ScriptedDetector(id = "deep", minDepth = Depth.FULL)
        ).run(Depth.QUICK)

        val byId = result.runs.associateBy { it.detectorId }
        assertThat(byId.getValue("deep").outcome).isEqualTo(RunOutcome.SKIPPED_FOR_DEPTH)
        assertThat(byId.getValue("deep").durationMillis).isEqualTo(-1L)
        assertThat(byId.getValue("quick").outcome).isEqualTo(RunOutcome.FOUND_NOTHING)
    }

    @Test
    fun `a timeout is distinguishable from finding nothing`() = runTest {
        val result = engine(
            ScriptedDetector(id = "slow", stallFor = 10.seconds, budget = 20.milliseconds),
            budget = 20.milliseconds
        ).run(Depth.FULL)

        assertThat(result.runs.single().outcome).isEqualTo(RunOutcome.TIMED_OUT)
    }

    @Test
    fun `every applicable detector appears exactly once`() = runTest {
        // If a detector could go missing from the list, a reader would take its absence for
        // "not registered" rather than "we lost it".
        val detectors = (1..6).map { ScriptedDetector(id = "d$it") }
        val result = engine(*detectors.toTypedArray()).run(Depth.FULL)

        assertThat(result.runs.map { it.detectorId })
            .containsExactlyElementsIn(detectors.map { it.id })
    }

    // --- what diagnostics must never do ---------------------------------------------------

    @Test
    fun `diagnostics are not part of the report and cannot reach the wire`() {
        // Hard rule 9 and ADR-0007: nothing in a report may raise trust, and "seventeen checks
        // found nothing" is precisely that — cheaper to forge than the evidence it stands for.
        // This asserts the property structurally: IntegrityReport has no field that could
        // carry a DetectorRun, so canonicalJson cannot emit one.
        val reportFields = IntegrityReport::class.java.declaredFields.map { it.type.name }

        assertThat(reportFields).doesNotContain(IntegrityDiagnostics::class.java.name)
        assertThat(reportFields).doesNotContain(DetectorRun::class.java.name)
        assertThat(reportFields.none { it.contains("Diagnostic", ignoreCase = true) }).isTrue()
        assertThat(reportFields.none { it.contains("DetectorRun", ignoreCase = true) }).isTrue()
    }

    @Test
    fun `FOUND_NOTHING is the outcome a hidden compromise also produces`() = runTest {
        // Not a behavioural assertion so much as a pinned reading of the vocabulary: a detector
        // that looked and saw nothing, and a detector defeated by a cloak, are the same value.
        // Anything downstream that treats FOUND_NOTHING as evidence of health is wrong, and
        // this test exists so that changing the enum forces someone to read that sentence.
        val looked = engine(ScriptedDetector(id = "clean-device")).run(Depth.FULL)
        val defeated = engine(ScriptedDetector(id = "cloaked-device")).run(Depth.FULL)

        assertThat(looked.runs.single().outcome).isEqualTo(defeated.runs.single().outcome)
        assertThat(looked.runs.single().outcome).isEqualTo(RunOutcome.FOUND_NOTHING)
    }
}
