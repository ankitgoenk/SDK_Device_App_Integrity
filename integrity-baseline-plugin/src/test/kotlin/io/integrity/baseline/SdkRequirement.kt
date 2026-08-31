package io.integrity.baseline

/**
 * What to do when a functional test cannot find an Android SDK.
 *
 * Extracted from the test so the decision itself is testable. A guard that silently chooses
 * "skip" is indistinguishable from a passing test, and this repository has already shipped one
 * of those.
 */
internal enum class SdkRequirement {
    /** An SDK is present; run. */
    OK,

    /** No SDK on a CI runner. A broken workflow, not an environment fact. */
    FAIL_CI,

    /** No SDK locally, where lacking one is reasonable. */
    SKIP_LOCAL;

    companion object {
        fun of(sdk: String?, isCi: Boolean): SdkRequirement = when {
            sdk != null -> OK
            isCi -> FAIL_CI
            else -> SKIP_LOCAL
        }
    }
}
