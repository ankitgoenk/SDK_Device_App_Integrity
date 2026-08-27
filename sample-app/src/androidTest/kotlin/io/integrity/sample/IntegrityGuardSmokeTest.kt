package io.integrity.sample

import androidx.test.ext.junit.runners.AndroidJUnit4
import io.integrity.core.Category
import io.integrity.core.Confidence
import io.integrity.core.Depth
import io.integrity.core.IntegrityGuard
import io.integrity.core.SignalId
import io.integrity.core.Verdict
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * End-to-end on a real runtime: the Application initialises the SDK, the engine dispatches
 * the registered detectors, and scoring produces a verdict.
 *
 * The assertions are deliberately about invariants rather than about what this particular
 * emulator image happens to contain. A CI emulator is typically a `test-keys` build that
 * ships `su`, so the root detectors do fire here — asserting "no signals" would be
 * asserting a property of the runner, and would break the moment the image changed.
 */
@RunWith(AndroidJUnit4::class)
class IntegrityGuardSmokeTest {

    @Test
    fun sdkIsInitialisedByTheApplication() {
        assertTrue("SampleApplication.onCreate should have initialised the SDK", IntegrityGuard.isInitialized())
    }

    @Test
    fun engineDispatchesDetectorsOnADevice() = runBlocking {
        val report = IntegrityGuard.evaluate(Depth.FULL, force = true)

        assertTrue("the engine should have run at least one detector", report.coverage > 0f)
        assertTrue("coverage cannot exceed 1", report.coverage <= 1f)
    }

    /** Hard rule 6, checked end-to-end: a new signal must not be able to enforce anything. */
    @Test
    fun newSignalsCannotMoveTheVerdict() = runBlocking {
        val report = IntegrityGuard.evaluate(Depth.FULL, force = true)

        assertEquals(
            "root signals ship INFORMATIONAL, so they must contribute nothing to the score",
            0,
            report.riskScore
        )
        assertEquals(Verdict.NO_EVIDENCE_OF_COMPROMISE, report.verdict)
    }

    /** Privacy rules P4/P5, checked on the real evidence the detectors produce. */
    @Test
    fun evidenceNeverContainsPathsOrClearPackageNames() = runBlocking {
        val report = IntegrityGuard.evaluate(Depth.FULL, force = true)

        report.signals.forEach { signal ->
            signal.evidence.forEach { (key, value) ->
                assertTrue("$key leaked a path: $value", !value.contains("/"))
                assertTrue("$key leaked a package name: $value", !value.contains("com."))
            }
        }
    }

    @Test
    fun everySignalBelongsToARegisteredCategory() = runBlocking {
        val report = IntegrityGuard.evaluate(Depth.FULL, force = true)

        val registered = setOf(Category.ROOT, Category.APP_TAMPER, Category.META)
        report.signals.forEach { signal ->
            assertTrue("unexpected category ${signal.category}", signal.category in registered)
        }
    }

    /**
     * The sample deliberately configures no signing pin, so the signature detector cannot
     * reach a conclusion. It must say so rather than stay silent: silence would be
     * indistinguishable from "this APK is correctly signed".
     */
    @Test
    fun anUnconfiguredSignatureCheckReportsInconclusiveRatherThanClean() = runBlocking {
        val report = IntegrityGuard.evaluate(Depth.FULL, force = true)

        val signature = report.signals.single { it.id == SignalId.APP_SIGNATURE_MISMATCH }
        assertEquals(Confidence.INCONCLUSIVE, signature.confidence)
        assertEquals("no_pin_configured", signature.evidence["reason"])
    }

    /** Coverage must stay honest: inconclusive detectors are not counted as covered. */
    @Test
    fun coverageReflectsOnlyDetectorsThatReachedAConclusion() = runBlocking {
        val report = IntegrityGuard.evaluate(Depth.FULL, force = true)

        assertTrue("coverage should be below 1 while some detectors are inconclusive", report.coverage < 1f)
    }

    @Test
    fun repeatedEvaluationIsServedFromCache() = runBlocking {
        val first = IntegrityGuard.evaluate(Depth.FULL, force = true)
        val second = IntegrityGuard.evaluate(Depth.FULL)

        assertEquals(first.reportId, second.reportId)
    }
}
