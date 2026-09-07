package io.integrity.core

import com.google.common.truth.Truth.assertThat
import org.junit.Test

/**
 * The derivation both ends of the wire depend on.
 *
 * `SubmittedReports` computes a signal's category from its id rather than reading it off the
 * wire, and [Signal] now defaults to the same derivation. That only closes the client/server
 * gap while the two agree — so what matters here is that the mapping is *total* over the ids
 * that actually exist, and that every constant resolves to the family its catalogue section
 * places it in.
 *
 * An id from no known family returning null is a supported case, not a hole: an integrator
 * feeding their own attestation verdict in may use one, and `DETECTION_TRIAGE.md` §8 says so.
 */
class SignalCategoriesTest {

    private val constants = listOf(
        SignalId.ROOT_SU_BINARY to Category.ROOT,
        SignalId.ROOT_MANAGER_PACKAGE to Category.ROOT,
        SignalId.ROOT_DANGEROUS_PROPS to Category.ROOT,
        SignalId.ROOT_PROP_SPOOF to Category.ROOT,
        SignalId.HOOK_SELF_TEXT_MISMATCH to Category.HOOKING,
        SignalId.HOOK_UNEXPECTED_MODULE to Category.HOOKING,
        SignalId.APP_SIGNATURE_MISMATCH to Category.APP_TAMPER,
        SignalId.APP_DEX_DIGEST_MISMATCH to Category.APP_TAMPER,
        SignalId.APP_NATIVE_LIB_MISMATCH to Category.APP_TAMPER,
        SignalId.ENV_NO_DEVICE_LOCK to Category.ENVIRONMENT,
        SignalId.ATT_APP_NOT_RECOGNISED to Category.ATTESTATION,
        SignalId.META_DETECTOR_TIMEOUT to Category.META,
        SignalId.META_DETECTOR_ERROR to Category.META,
        SignalId.META_NATIVE_UNAVAILABLE to Category.META,
        SignalId.META_NATIVE_NOT_CONFIGURED to Category.META,
        SignalId.META_NATIVE_FAILED to Category.META,
        SignalId.META_CONFIG_INVALID to Category.META,
        SignalId.META_VISIBILITY_RESTRICTED to Category.META,
        SignalId.SRV_REPORT_SIGNATURE_INVALID to Category.APP_TAMPER,
        SignalId.SRV_REPORT_LABEL_UNRECOGNISED to Category.APP_TAMPER
    )

    @Test
    fun `every SignalId constant resolves to its catalogue family`() {
        constants.forEach { (id, expected) ->
            assertThat(SignalCategories.of(id)).isEqualTo(expected)
        }
    }

    @Test
    fun `the mapping is total over every constant`() {
        // A prefix added to SignalId without one here would return null and fall back to the
        // declared value, which is the silent divergence this whole derivation exists to close.
        val unmapped = constants.map { it.first }.filter { SignalCategories.of(it) == null }

        assertThat(unmapped).isEmpty()
    }

    @Test
    fun `an id from no known family is null rather than guessed`() {
        // Supported: an integrator's own id. It keeps whatever category it arrived with.
        assertThat(SignalCategories.of(SignalId("PARTNER_OWN_CHECK"))).isNull()
    }

    @Test
    fun `Signal takes its category from the id by default`() {
        // The point of the default: the correct value is the one you get for free, so a
        // detector cannot drift from the backend by forgetting rather than by deciding.
        val signal = Signal(
            id = SignalId.HOOK_UNEXPECTED_MODULE,
            confidence = Confidence.CONFIRMED
        )

        assertThat(signal.category).isEqualTo(Category.HOOKING)
    }

    @Test
    fun `an explicit category still wins, for ids this build does not know`() {
        val signal = Signal(
            id = SignalId("PARTNER_OWN_CHECK"),
            category = Category.ENVIRONMENT,
            confidence = Confidence.LIKELY
        )

        assertThat(signal.category).isEqualTo(Category.ENVIRONMENT)
    }

    @Test
    fun `VIRT and EMU share the emulation family`() {
        // They are catalogued in one section and scored together; the prefixes differ and the
        // family does not.
        assertThat(SignalCategories.of(SignalId("VIRT_DUAL_INSTANCE")))
            .isEqualTo(SignalCategories.of(SignalId("EMU_BUILD_FINGERPRINT")))
    }
}
