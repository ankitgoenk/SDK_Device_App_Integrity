package io.integrity.sample

import androidx.test.ext.junit.runners.AndroidJUnit4
import io.integrity.core.Depth
import io.integrity.core.IntegrityGuard
import io.integrity.core.Verdict
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The end-to-end check phase 0 exists to prove, now running against the phase 1 engine:
 * the SDK is initialised by a real Application on a real Android runtime, the engine
 * dispatches the registered detectors, and scoring produces a verdict.
 */
@RunWith(AndroidJUnit4::class)
class IntegrityGuardSmokeTest {

    @Test
    fun sdkIsInitialisedByTheApplication() {
        assertTrue("SampleApplication.onCreate should have initialised the SDK", IntegrityGuard.isInitialized())
    }

    @Test
    fun engineDispatchesTheRegisteredDetector() = runBlocking {
        val report = IntegrityGuard.evaluate(Depth.FULL, force = true)

        // HostDetector is the only registered detector and it concludes cleanly, so the
        // engine must report full coverage — the value that says a clean report means
        // something. Anything less would mean the detector never ran.
        assertEquals(1f, report.coverage, 0f)
        assertTrue("a clean sweep should not invent signals", report.signals.isEmpty())
        assertEquals(0, report.riskScore)
        assertEquals(Verdict.TRUSTED, report.verdict)
    }

    @Test
    fun repeatedEvaluationIsServedFromCache() = runBlocking {
        val first = IntegrityGuard.evaluate(Depth.FULL, force = true)
        val second = IntegrityGuard.evaluate(Depth.FULL)

        assertEquals(first.reportId, second.reportId)
    }

    @Test
    fun currentReportIsSafeToCallOnAnyThread() {
        val report = IntegrityGuard.currentReport()

        assertTrue(report.reportId.isNotEmpty())
    }
}
