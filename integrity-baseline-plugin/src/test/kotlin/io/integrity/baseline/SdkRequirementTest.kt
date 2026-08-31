package io.integrity.baseline

import com.google.common.truth.Truth.assertThat
import org.junit.Test

/**
 * The guard's own behaviour, which is otherwise unobservable: you cannot easily run the suite
 * on a CI runner with the SDK removed to find out what it does.
 */
class SdkRequirementTest {

    @Test
    fun `an sdk means run, wherever we are`() {
        assertThat(SdkRequirement.of("/opt/android", isCi = true)).isEqualTo(SdkRequirement.OK)
        assertThat(SdkRequirement.of("/opt/android", isCi = false)).isEqualTo(SdkRequirement.OK)
    }

    @Test
    fun `no sdk in CI is a failure, never a skip`() {
        // The point of the whole change: a green CI job must mean the wiring was exercised.
        assertThat(SdkRequirement.of(null, isCi = true)).isEqualTo(SdkRequirement.FAIL_CI)
    }

    @Test
    fun `no sdk locally is a skip, because lacking one is reasonable`() {
        assertThat(SdkRequirement.of(null, isCi = false)).isEqualTo(SdkRequirement.SKIP_LOCAL)
    }
}
