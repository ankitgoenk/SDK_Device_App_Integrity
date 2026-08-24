package io.integrity.sample

import androidx.test.ext.junit.runners.AndroidJUnit4
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
 * The end-to-end check phase 0 exists to prove: the SDK is initialised by a real
 * Application on a real Android runtime, and the public API answers.
 *
 * It deliberately asserts the *scaffold's* behaviour — UNKNOWN plus
 * META_ENGINE_NOT_IMPLEMENTED — so it fails loudly when the phase 1 engine lands and
 * someone forgets to update it.
 */
@RunWith(AndroidJUnit4::class)
class IntegrityGuardSmokeTest {

    @Test
    fun sdkIsInitialisedByTheApplication() {
        assertTrue("SampleApplication.onCreate should have initialised the SDK", IntegrityGuard.isInitialized())
    }

    @Test
    fun evaluateReturnsUnknownWhileTheEngineIsAScaffold() = runBlocking {
        val report = IntegrityGuard.evaluate(Depth.FULL, force = true)

        assertEquals(Verdict.UNKNOWN, report.verdict)
        assertEquals(0, report.riskScore)
        assertEquals(0f, report.coverage, 0f)
        assertTrue(report.hasSignal(SignalId.META_ENGINE_NOT_IMPLEMENTED))
    }

    @Test
    fun currentReportIsSafeToCallOnAnyThread() {
        val report = IntegrityGuard.currentReport()

        assertEquals(Verdict.UNKNOWN, report.verdict)
        assertTrue(report.reportId.isNotEmpty())
    }
}
