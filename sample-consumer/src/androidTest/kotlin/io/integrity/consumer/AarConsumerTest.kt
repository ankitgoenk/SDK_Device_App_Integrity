package io.integrity.consumer

import androidx.test.ext.junit.runners.AndroidJUnit4
import io.integrity.core.Depth
import io.integrity.core.IntegrityGuard
import io.integrity.core.SignalId
import io.integrity.core.Verdict
import io.integrity.detector.environment.EnvironmentDetectors
import io.integrity.detector.root.RootDetectors
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Proves the chain a project dependency cannot: AAR packaging -> Maven coordinates ->
 * an unrelated application -> Android runtime -> SDK API.
 */
@RunWith(AndroidJUnit4::class)
class AarConsumerTest {

    @Test
    fun sdkClassesLoadFromThePublishedAars() {
        assertNotNull(RootDetectors.all())
        assertNotNull(EnvironmentDetectors.all())
    }

    @Test
    fun applicationInitialisedTheSdk() {
        assertTrue(IntegrityGuard.isInitialized())
    }

    @Test
    fun evaluateAnswersAcrossTheAarBoundary() = runBlocking {
        val report = IntegrityGuard.evaluate(Depth.FULL, force = true)

        assertEquals(Verdict.UNKNOWN, report.verdict)
        assertTrue(report.hasSignal(SignalId.META_ENGINE_NOT_IMPLEMENTED))
        assertTrue(report.reportId.isNotEmpty())
    }
}
