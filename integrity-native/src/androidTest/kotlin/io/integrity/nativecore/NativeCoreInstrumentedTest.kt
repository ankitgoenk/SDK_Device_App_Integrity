package io.integrity.nativecore

import androidx.test.ext.junit.runners.AndroidJUnit4
import io.integrity.core.IntegrityReport
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The walking skeleton, on a real device: the `.so` is packaged, loads, registers its
 * methods dynamically, answers, and fails safely.
 *
 * Phase 3a exists to prove exactly this much before any detection logic is added, so that
 * a later failure in phase 3b cannot be confused with a failure to ship native code.
 */
@RunWith(AndroidJUnit4::class)
class NativeCoreInstrumentedTest {

    private fun core(token: String = IntegrityReport.SDK_VERSION, loader: NativeLibraryLoader = SystemLibraryLoader) =
        NativeCore(expectedByHost = true, expectedToken = token, loader = loader)

    @Test
    fun theLibraryLoadsAndIdentifiesItselfAsThisBuild() {
        assertEquals(NativeOutcome.OK, core().evaluate())
    }

    @Test
    fun aLibraryFromAnotherBuildWouldBeAMismatch() {
        // Equivalent, from the check's point of view, to a substituted .so: the token the
        // SDK expects and the token compiled into the library disagree.
        assertEquals(NativeOutcome.LIBRARY_MISMATCH, core(token = "0.0.0-not-this-build").evaluate())
    }

    @Test
    fun aMissingLibraryIsUnavailableAndDoesNotCrashTheProcess() {
        val missing = object : NativeLibraryLoader {
            override fun load(name: String) = System.loadLibrary("integrity-does-not-exist")
        }

        assertEquals(NativeOutcome.UNAVAILABLE, core(loader = missing).evaluate())
    }

    @Test
    fun aHostThatDidNotAskForNativeGetsNotConfigured() {
        val outcome = NativeCore(
            expectedByHost = false,
            expectedToken = IntegrityReport.SDK_VERSION
        ).evaluate()

        assertEquals(NativeOutcome.NOT_CONFIGURED, outcome)
    }

    /**
     * A C++ exception thrown inside the boundary must be contained and turned into a
     * status code. If this test crashes the process instead of failing, the containment
     * is broken — which for an SDK inside someone else's app is the worst outcome there
     * is, worse than any missed detection.
     */
    @Test
    fun aNativeFailureIsContainedAtTheBoundary() {
        SystemLibraryLoader.load(NativeCore.LIBRARY_NAME)

        assertEquals(EXPECTED_PROVOKED_FAILURE, NativeBridge.provokeFailure())
    }

    private companion object {
        /** integrity::kProvokedFailure in selfcheck.h. */
        const val EXPECTED_PROVOKED_FAILURE = 3
    }
}
