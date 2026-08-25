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

    /**
     * A challenged evaluation is never answered from cache.
     *
     * The challenge exists to show the evidence was gathered for *this* request. Serving it
     * from a sweep that finished minutes ago, with the new nonce stamped on, is replay
     * wearing a convenience parameter.
     */
    @Test
    fun `a challenged evaluation never reads the cache`() {
        assertThat(IntegrityGuard.mayServeFromCache(force = false, challenge = null)).isTrue()
        assertThat(IntegrityGuard.mayServeFromCache(force = false, challenge = "nonce")).isFalse()
        assertThat(IntegrityGuard.mayServeFromCache(force = true, challenge = null)).isFalse()
        assertThat(IntegrityGuard.mayServeFromCache(force = true, challenge = "nonce")).isFalse()
    }

    /**
     * And never enters it, which is the easier half to miss: a cached challenged report
     * would later answer a plain evaluate() still carrying a nonce the caller never saw.
     */
    @Test
    fun `a challenged report never enters the cache`() {
        assertThat(IntegrityGuard.mayCache(challenge = null)).isTrue()
        assertThat(IntegrityGuard.mayCache(challenge = "nonce")).isFalse()
    }
}
