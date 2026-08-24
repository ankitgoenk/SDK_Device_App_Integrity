package io.integrity.detector.app

import com.google.common.truth.Truth.assertThat
import io.integrity.core.Category
import io.integrity.core.Policy
import io.integrity.core.SignalId
import io.integrity.core.Weight
import org.junit.Test

class AppDetectorsTest {

    @Test
    fun `detectors are registered in the app-tamper category`() {
        val detectors = AppDetectors.all()

        assertThat(detectors).isNotEmpty()
        assertThat(detectors.map { it.category }.toSet()).containsExactly(Category.APP_TAMPER)
    }

    @Test
    fun `signature mismatch ships informational so it cannot enforce by default`() {
        assertThat(Policy.balanced().weightOf(SignalId.APP_SIGNATURE_MISMATCH))
            .isEqualTo(Weight.INFORMATIONAL)
    }

    @Test
    fun `promotion is explicit and opt-in`() {
        assertThat(AppDetectors.proposedWeights(Policy.balanced()).weightOf(SignalId.APP_SIGNATURE_MISMATCH))
            .isEqualTo(Weight.HIGH)
    }
}
