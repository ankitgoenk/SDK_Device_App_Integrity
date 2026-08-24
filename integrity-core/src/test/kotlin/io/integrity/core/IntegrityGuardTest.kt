package io.integrity.core

import com.google.common.truth.Truth.assertThat
import kotlinx.coroutines.test.runTest
import org.junit.Before
import org.junit.Test

class IntegrityGuardTest {

    @Before
    fun reset() {
        IntegrityGuard.shutdown()
    }

    @Test
    fun `calling before initialize reports unknown rather than throwing`() {
        val report = IntegrityGuard.currentReport()

        assertThat(report.verdict).isEqualTo(Verdict.UNKNOWN)
        assertThat(report.hasSignal(SignalId.META_CONFIG_INVALID)).isTrue()
    }

    @Test
    fun `evaluating before initialize reports unknown rather than throwing`() = runTest {
        val report = IntegrityGuard.evaluate(Depth.FULL)

        assertThat(report.verdict).isEqualTo(Verdict.UNKNOWN)
        assertThat(report.hasSignal(SignalId.META_CONFIG_INVALID)).isTrue()
        assertThat(report.coverage).isEqualTo(0f)
    }

    @Test
    fun `isInitialized is false before initialize`() {
        assertThat(IntegrityGuard.isInitialized()).isFalse()
    }
}
