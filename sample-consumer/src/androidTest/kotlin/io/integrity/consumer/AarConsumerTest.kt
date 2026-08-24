package io.integrity.consumer

import androidx.test.ext.junit.runners.AndroidJUnit4
import io.integrity.core.Depth
import io.integrity.core.IntegrityGuard
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

        // The detector families are still empty (phases 2-7), so nothing was applicable
        // and coverage is zero. The SDK must therefore say UNKNOWN, never TRUSTED: a
        // report with no coverage is not evidence that the device is clean.
        assertEquals(0f, report.coverage, 0f)
        assertEquals(Verdict.UNKNOWN, report.verdict)
        assertTrue(report.reportId.isNotEmpty())
    }
}
