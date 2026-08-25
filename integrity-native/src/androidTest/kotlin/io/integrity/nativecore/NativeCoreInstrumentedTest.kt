package io.integrity.nativecore

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.integrity.core.IntegrityReport
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
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

    /**
     * The measurement that decides whether HOOK_SELF_TEXT_MISMATCH is worth building.
     *
     * The whole design rests on one assumption: on a legitimate Android process, the
     * executable pages of this library match the bytes in the `.so` they were loaded from.
     * If that is false — text relocations being the plausible reason — then what would get
     * built is a very thorough false-positive generator, so the assumption is tested before
     * any detector exists. See `docs/detectors/HOOK_SELF_TEXT_MISMATCH.md`.
     *
     * Three assertions, not one. `0 differences` must not be able to mean `0 mappings
     * inspected`, or this recreates exactly the silence the last several changes removed.
     */
    @Test
    fun aCleanProcessMatchesTheLibraryItWasLoadedFrom() {
        SystemLibraryLoader.load(NativeCore.LIBRARY_NAME)

        val measurement = NativeBridge.measureSelfText()
        assertNotNull("the measurement call itself failed", measurement)
        val values = measurement!!

        val status = values[NativeCore.MEASURE_STATUS].toInt()
        val mappings = values[NativeCore.MEASURE_MAPPINGS]
        val compared = values[NativeCore.MEASURE_BYTES_COMPARED]
        val differing = values[NativeCore.MEASURE_BYTES_DIFFERING]
        val firstAt = values[NativeCore.MEASURE_FIRST_DIFFERENCE]

        // Reported unconditionally: the number is the deliverable of this change, and a
        // non-zero result is a finding rather than a flake.
        Log.i(
            "IntegritySelfText",
            "self-text measurement: status=$status mappings=$mappings " +
                "compared=$compared differing=$differing firstAt=$firstAt"
        )

        assertEquals(
            "the measurement could not complete; that is 'not checked', never 'clean'",
            NativeCore.STATUS_OK,
            status
        )
        assertTrue("no executable mapping of this library was inspected", mappings > 0)
        assertTrue("no bytes were compared, so a zero difference count proves nothing", compared > 0)
        assertEquals(
            "this library's executable pages differ from the .so on disk at offset $firstAt " +
                "($differing of $compared bytes). If this fires on a clean image, the " +
                "HOOK_SELF_TEXT_MISMATCH design does not proceed in its current form.",
            0L,
            differing
        )
    }
}
