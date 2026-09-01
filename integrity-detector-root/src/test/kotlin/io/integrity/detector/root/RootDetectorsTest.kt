package io.integrity.detector.root

import com.google.common.truth.Truth.assertThat
import io.integrity.core.Category
import io.integrity.core.Policy
import io.integrity.core.SignalId
import io.integrity.core.Weight
import org.junit.Test

class RootDetectorsTest {

    @Test
    fun `all detectors are registered and in the root category`() {
        val detectors = RootDetectors.all()

        assertThat(detectors).hasSize(4)
        assertThat(detectors.map { it.category }.toSet()).containsExactly(Category.ROOT)
        assertThat(detectors.map { it.id }).containsNoDuplicates()
    }

    @Test
    fun `new signals ship informational so a host cannot enforce on them by accident`() {
        val policy = Policy.balanced()

        assertThat(policy.weightOf(SignalId.ROOT_SU_BINARY)).isEqualTo(Weight.INFORMATIONAL)
        assertThat(policy.weightOf(SignalId.ROOT_MANAGER_PACKAGE)).isEqualTo(Weight.INFORMATIONAL)
        assertThat(policy.weightOf(SignalId.ROOT_DANGEROUS_PROPS)).isEqualTo(Weight.INFORMATIONAL)
        assertThat(policy.weightOf(SignalId.ROOT_PROP_SPOOF)).isEqualTo(Weight.INFORMATIONAL)
    }

    @Test
    fun `proposed weights are opt-in and applied only when a host asks`() {
        val promoted = RootDetectors.proposedWeights(Policy.balanced())

        assertThat(promoted.weightOf(SignalId.ROOT_SU_BINARY)).isEqualTo(Weight.HIGH)
        assertThat(promoted.weightOf(SignalId.ROOT_MANAGER_PACKAGE)).isEqualTo(Weight.MEDIUM)
        assertThat(promoted.weightOf(SignalId.ROOT_DANGEROUS_PROPS)).isEqualTo(Weight.LOW)
        assertThat(promoted.weightOf(SignalId.ROOT_PROP_SPOOF)).isEqualTo(Weight.HIGH)
    }
}
