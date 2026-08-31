package io.integrity.nativecore

import com.google.common.truth.Truth.assertThat
import io.integrity.core.Confidence
import io.integrity.core.DetectionContext
import io.integrity.core.IntegrityConfig
import io.integrity.core.SignalId
import kotlinx.coroutines.test.runTest
import org.junit.Test

/**
 * Decision-table tests for `HOOK_SELF_TEXT_MISMATCH`.
 *
 * The measurement itself is tested natively, at three widths and against a mutation gate.
 * What is checked here is the translation from counters to a claim — and specifically that
 * every way of failing to measure produces INCONCLUSIVE with a reason, rather than the
 * silence that would read as "clean".
 */
class SelfTextDetectorTest {

    private object NoContext : DetectionContext {
        override val appContext get() = error("not needed: this detector never touches Android")
        override val config = IntegrityConfig.Builder().build()
    }

    /**
     * Records whether the detector loaded the library before calling into it.
     *
     * The regression this exists for is invisible to a test that assumes the library is
     * already there — which every test here did, which is why the defect reached a device.
     */
    private class RecordingLoader(private val succeeds: Boolean = true) : NativeLibraryLoader {
        var loadCount = 0
            private set

        override fun load(name: String) {
            loadCount++
            if (!succeeds) throw UnsatisfiedLinkError("no $name in this test")
        }
    }

    private class Fake(private val values: LongArray?) : NativeApi {
        override fun selfCheck(expectedToken: String) = NativeCore.STATUS_OK
        override fun probeUnmappedRead() = NativeCore.STATUS_UNAVAILABLE
        override fun probeMappedRead() = NativeCore.STATUS_OK
        override fun measureSelfText(): LongArray? = values
        override fun measureSelfTextFrom(mapsPath: String): LongArray? = values
    }

    /** Every decision-table test below is about the counters, so the library always loads. */
    private fun detector(values: LongArray?, loader: NativeLibraryLoader = RecordingLoader()) =
        SelfTextDetector(Fake(values), expectedByHost = true, loader = loader)

    private fun measurement(
        status: Int = NativeCore.STATUS_OK,
        mappings: Long = 1,
        compared: Long = 12288,
        differing: Long = 0,
        firstAt: Long = 0,
        reason: Long = 0
    ) = longArrayOf(status.toLong(), mappings, compared, differing, firstAt, reason)

    @Test
    fun aMatchingLibraryProducesNoSignal() = runTest {
        val signals = detector(measurement()).detect(NoContext)

        assertThat(signals).isEmpty()
    }

    @Test
    fun aDifferenceIsPossibleAndNeverHigher() = runTest {
        val signals = detector(measurement(differing = 4, firstAt = 512))
            .detect(NoContext)

        assertThat(signals).hasSize(1)
        val signal = signals.single()
        assertThat(signal.id).isEqualTo(SignalId.HOOK_SELF_TEXT_MISMATCH)
        // Never CONFIRMED. The bytes are exact; what they mean is not, and four cheap
        // bypasses mean a silent result proves nothing either.
        assertThat(signal.confidence).isEqualTo(Confidence.POSSIBLE)
        assertThat(signal.evidence["bytesDiffering"]).isEqualTo("4")
        assertThat(signal.evidence["firstDifferenceAt"]).isEqualTo("512")
        assertThat(signal.evidence["bytesCompared"]).isEqualTo("12288")
    }

    @Test
    fun evidenceCarriesNothingIdentifying() = runTest {
        val signals = detector(measurement(differing = 1)).detect(NoContext)

        signals.single().evidence.forEach { (key, value) ->
            assertThat(value).doesNotContain("/")
            assertThat(value).doesNotContain("com.")
        }
    }

    @Test
    fun everyUnavailableReasonIsReportedDistinctly() = runTest {
        val expected = mapOf(
            NativeCore.REASON_MAPS_UNREADABLE to "maps_unreadable",
            NativeCore.REASON_SELF_MAPPING_NOT_FOUND to "self_mapping_not_found",
            NativeCore.REASON_LIBRARY_FILE_UNREADABLE to "library_file_unreadable",
            NativeCore.REASON_MEMORY_UNREADABLE to "memory_unreadable",
            NativeCore.REASON_NOTHING_COMPARED to "nothing_compared"
        )

        expected.forEach { (code, reason) ->
            val signals = detector(
                measurement(status = NativeCore.STATUS_UNAVAILABLE, reason = code.toLong())
            ).detect(NoContext)

            val signal = signals.single()
            assertThat(signal.confidence).isEqualTo(Confidence.INCONCLUSIVE)
            assertThat(signal.evidence["reason"]).isEqualTo(reason)
        }
    }

    /** Hard rule 2: a check that could not run says so. It never returns nothing. */
    @Test
    fun aFailedCallIsInconclusiveRatherThanSilent() = runTest {
        val signals = detector(null).detect(NoContext)

        assertThat(signals.single().confidence).isEqualTo(Confidence.INCONCLUSIVE)
        assertThat(signals.single().evidence["reason"]).isEqualTo("call_failed")
    }

    @Test
    fun aTruncatedResultIsInconclusiveRatherThanIndexedInto() = runTest {
        val signals = detector(longArrayOf(0, 1)).detect(NoContext)

        assertThat(signals.single().evidence["reason"]).isEqualTo("malformed_result")
    }

    /**
     * The defence in depth that matters most: a measurement claiming success while having
     * compared nothing must not read as clean. The native side already refuses this, so
     * this asserts the detector does not depend on it.
     */
    @Test
    fun successWithNothingComparedIsNotACleanResult() = runTest {
        val signals = detector(measurement(compared = 0)).detect(NoContext)

        assertThat(signals.single().confidence).isEqualTo(Confidence.INCONCLUSIVE)
        assertThat(signals.single().evidence["reason"]).isEqualTo("nothing_compared")
    }

    // --- the regression: this detector must not depend on another one having run ---------

    @Test
    fun theLibraryIsLoadedBeforeTheCallRatherThanAssumedLoaded() = runTest {
        // The engine dispatches detectors concurrently. This one used to call straight into
        // JNI and depend on NativeIntegrityDetector having won the race, which on a Pixel
        // 10a it did not: a healthy device reported `call_failed`.
        val loader = RecordingLoader()

        detector(measurement(), loader).detect(NoContext)

        assertThat(loader.loadCount).isEqualTo(1)
    }

    @Test
    fun aLibraryThatWillNotLoadIsUnavailableRatherThanACallFailure() = runTest {
        // Two different facts about a device. Collapsing them is what hid the race: a
        // missing library and a broken call both read as `call_failed`.
        val signals = detector(measurement(), RecordingLoader(succeeds = false)).detect(NoContext)

        assertThat(signals).hasSize(1)
        assertThat(signals[0].confidence).isEqualTo(Confidence.INCONCLUSIVE)
        assertThat(signals[0].evidence["reason"]).isEqualTo("library_unavailable")
    }

    @Test
    fun aHostThatDidNotPackageNativeIsAConfigurationFactNotAFailure() = runTest {
        val loader = RecordingLoader()
        val signals = SelfTextDetector(Fake(measurement()), expectedByHost = false, loader = loader)
            .detect(NoContext)

        assertThat(signals[0].evidence["reason"]).isEqualTo("not_configured")
        // And it must not have gone looking for a library the host never shipped.
        assertThat(loader.loadCount).isEqualTo(0)
    }

    @Test
    fun everyPreMeasurementFailureHasItsOwnReason() = runTest {
        // The reasons must stay distinguishable; that is the property the C++ header states
        // for its own reason codes, and it now has to hold on the Kotlin side too.
        val reasons = listOf(
            detector(measurement(), RecordingLoader(succeeds = false)),
            detector(null),
            detector(longArrayOf(0, 1))
        ).map { it.detect(NoContext).single().evidence["reason"] }

        assertThat(reasons).containsExactly("library_unavailable", "call_failed", "malformed_result")
        assertThat(reasons.toSet()).hasSize(reasons.size)
    }
}
