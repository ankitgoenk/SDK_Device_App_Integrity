package io.integrity.core

import com.google.common.truth.Truth.assertThat
import org.junit.Test

class IntegrityConfigTest {

    @Test
    fun `signing pins are normalised so colon-separated input matches`() {
        val config = IntegrityConfig.Builder()
            .expectedSigningCertSha256("a1:b2:c3")
            .build()

        assertThat(config.expectedSigningCertSha256).containsExactly("A1B2C3")
    }

    @Test
    fun `config defaults are conservative`() {
        val config = IntegrityConfig.Builder().build()

        assertThat(config.detectors).isEmpty()
        assertThat(config.sink).isNull()
        assertThat(config.detectorBudget).isEqualTo(Detector.DEFAULT_BUDGET)
    }
}
