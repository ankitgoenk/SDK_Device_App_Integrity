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
     * The property that matters on a real device: an address that is never mapped produces
     * a status code, not a signal.
     *
     * This also confirms ADR-0005's flagged assumption — that reading through
     * /proc/self/mem turns a bad address into an errno on Android, not just on a desktop
     * kernel. SELinux policy, kernel version and OEM changes all get a say, so it is
     * asserted here rather than believed.
     */
    @Test
    fun anUnmappedAddressProducesAStatusRatherThanASignal() {
        SystemLibraryLoader.load(NativeCore.LIBRARY_NAME)

        assertEquals(NativeCore.STATUS_UNAVAILABLE, NativeBridge.probeUnmappedRead())
    }

    /**
     * The other direction, and the one the flip to `ANDROID_STL=none` / `-fno-exceptions`
     * makes worth asserting on a device.
     *
     * The test above passes just as happily against an implementation that reports
     * `kStatusUnavailable` for *every* address — which is precisely what `off_t`
     * truncation did on 32-bit ABIs. A build that became quietly more conservative would
     * look identical to a correct one, and the host tests cannot see it: they are compiled
     * by the host toolchain, not with the NDK settings this PR changes.
     *
     * So: a mapped address must still read, on a real device, under the shipped build
     * configuration. The native side also compares the bytes, because a read that reports
     * success while copying nothing is the same collapse in a different hat.
     */
    @Test
    fun aMappedAddressStillReadsSuccessfully() {
        SystemLibraryLoader.load(NativeCore.LIBRARY_NAME)

        assertEquals(NativeCore.STATUS_OK, NativeBridge.probeMappedRead())
    }
}
