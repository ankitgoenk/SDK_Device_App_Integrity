package io.integrity.core

import com.google.common.truth.Truth.assertThat
import org.junit.Test

class IntegrityReportTest {

    @Test
    fun `unknown report is never trusted and carries no score`() {
        val report = IntegrityReport.unknown(Depth.QUICK)

        assertThat(report.verdict).isEqualTo(Verdict.UNKNOWN)
        assertThat(report.riskScore).isEqualTo(0)
        assertThat(report.coverage).isEqualTo(0f)
    }

    @Test
    fun `report ids are unique per evaluation`() {
        val first = IntegrityReport.unknown(Depth.QUICK)
        val second = IntegrityReport.unknown(Depth.QUICK)

        assertThat(first.reportId).isNotEqualTo(second.reportId)
    }

    @Test
    fun `hasSignal finds a carried signal`() {
        val report = IntegrityReport.unknown(
            depth = Depth.FULL,
            signals = listOf(
                Signal(SignalId.META_NATIVE_UNAVAILABLE, Category.META, Confidence.CONFIRMED),
            ),
        )

        assertThat(report.hasSignal(SignalId.META_NATIVE_UNAVAILABLE)).isTrue()
        assertThat(report.hasSignal(SignalId.META_DETECTOR_TIMEOUT)).isFalse()
    }
}
