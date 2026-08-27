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

    /**
     * The native library has to arrive inside a published AAR and load in an unrelated
     * application. If it did not, this reports META_NATIVE_UNAVAILABLE instead of nothing.
     */
    @Test
    fun theNativeLibraryLoadsFromThePublishedAar() = runBlocking {
        val report = IntegrityGuard.evaluate(Depth.FULL, force = true)

        val nativeProblems = report.signals.filter {
            it.id == SignalId.META_NATIVE_UNAVAILABLE ||
                it.id == SignalId.META_NATIVE_FAILED ||
                it.id == SignalId.APP_NATIVE_LIB_MISMATCH
        }

        assertTrue(
            "native core did not load cleanly from the AAR: " +
                nativeProblems.joinToString { "${it.id}${it.evidence}" },
            nativeProblems.isEmpty()
        )
    }

    @Test
    fun evaluateAnswersAcrossTheAarBoundary() = runBlocking {
        val report = IntegrityGuard.evaluate(Depth.FULL, force = true)

        // The root detectors arrive from a published AAR, so this proves detection code —
        // not just the API surface — survives packaging and R8's consumer rules.
        assertTrue("root detectors from the AAR should have run", report.coverage > 0f)
        assertTrue(report.reportId.isNotEmpty())
    }

    @Test
    fun signalsFromTheAarCannotEnforceAnything() = runBlocking {
        val report = IntegrityGuard.evaluate(Depth.FULL, force = true)

        // Hard rule 6 holds across the artifact boundary too.
        assertEquals(0, report.riskScore)
        assertEquals(Verdict.NO_EVIDENCE_OF_COMPROMISE, report.verdict)
    }
}
