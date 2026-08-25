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

    private class Fake(private val values: LongArray?) : NativeApi {
        override fun selfCheck(expectedToken: String) = NativeCore.STATUS_OK
        override fun probeUnmappedRead() = NativeCore.STATUS_UNAVAILABLE
        override fun probeMappedRead() = NativeCore.STATUS_OK
        override fun measureSelfText(): LongArray? = values
        override fun measureSelfTextFrom(mapsPath: String): LongArray? = values
    }

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
        val signals = SelfTextDetector(Fake(measurement())).detect(NoContext)

        assertThat(signals).isEmpty()
    }

    @Test
    fun aDifferenceIsPossibleAndNeverHigher() = runTest {
        val signals = SelfTextDetector(Fake(measurement(differing = 4, firstAt = 512)))
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
        val signals = SelfTextDetector(Fake(measurement(differing = 1))).detect(NoContext)

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
            val signals = SelfTextDetector(
                Fake(measurement(status = NativeCore.STATUS_UNAVAILABLE, reason = code.toLong()))
            ).detect(NoContext)

            val signal = signals.single()
            assertThat(signal.confidence).isEqualTo(Confidence.INCONCLUSIVE)
            assertThat(signal.evidence["reason"]).isEqualTo(reason)
        }
    }

    /** Hard rule 2: a check that could not run says so. It never returns nothing. */
    @Test
    fun aFailedCallIsInconclusiveRatherThanSilent() = runTest {
        val signals = SelfTextDetector(Fake(null)).detect(NoContext)

        assertThat(signals.single().confidence).isEqualTo(Confidence.INCONCLUSIVE)
        assertThat(signals.single().evidence["reason"]).isEqualTo("call_failed")
    }

    @Test
    fun aTruncatedResultIsInconclusiveRatherThanIndexedInto() = runTest {
        val signals = SelfTextDetector(Fake(longArrayOf(0, 1))).detect(NoContext)

        assertThat(signals.single().evidence["reason"]).isEqualTo("malformed_result")
    }

    /**
     * The defence in depth that matters most: a measurement claiming success while having
     * compared nothing must not read as clean. The native side already refuses this, so
     * this asserts the detector does not depend on it.
     */
    @Test
    fun successWithNothingComparedIsNotACleanResult() = runTest {
        val signals = SelfTextDetector(Fake(measurement(compared = 0))).detect(NoContext)

        assertThat(signals.single().confidence).isEqualTo(Confidence.INCONCLUSIVE)
        assertThat(signals.single().evidence["reason"]).isEqualTo("nothing_compared")
    }
}
