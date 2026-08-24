package io.integrity.detector.app

import com.google.common.truth.Truth.assertThat
import io.integrity.core.Category
import io.integrity.core.Confidence
import io.integrity.core.IntegrityConfig
import io.integrity.core.SignalId
import kotlinx.coroutines.test.runTest
import org.junit.Test

class SignatureDetectorTest {

    private suspend fun detect(probe: SigningInfoProbe, config: IntegrityConfig) =
        SignatureDetector(probe).detect(FakeDetectionContext(config))

    @Test
    fun `the expected signing key produces no signal`() = runTest {
        val signals = detect(FakeSigningInfoProbe(), configPinning(APP_SIGNING_KEY))

        assertThat(signals).isEmpty()
    }

    @Test
    fun `an unknown certificate is a confirmed mismatch`() = runTest {
        val signals = detect(FakeSigningInfoProbe(signers = listOf(ATTACKER_KEY)), configPinning(APP_SIGNING_KEY))

        val signal = signals.single()
        assertThat(signal.id).isEqualTo(SignalId.APP_SIGNATURE_MISMATCH)
        assertThat(signal.category).isEqualTo(Category.APP_TAMPER)
        assertThat(signal.confidence).isEqualTo(Confidence.CONFIRMED)
    }

    @Test
    fun `a legitimately rotated key is not a mismatch`() = runTest {
        // Pinned before rotation; the app is now signed by the new key, and the platform
        // reports the old one as an ancestor.
        val probe = FakeSigningInfoProbe(
            signers = listOf(APP_SIGNING_KEY),
            lineage = setOf(ROTATED_FROM_KEY)
        )

        assertThat(detect(probe, configPinning(ROTATED_FROM_KEY))).isEmpty()
    }

    @Test
    fun `rotation is not honoured below api 28 where no lineage exists`() = runTest {
        val probe = FakeSigningInfoProbe(
            apiLevel = 27,
            signers = listOf(APP_SIGNING_KEY),
            lineage = setOf(ROTATED_FROM_KEY)
        )

        assertThat(detect(probe, configPinning(ROTATED_FROM_KEY))).hasSize(1)
    }

    @Test
    fun `a mismatch below api 28 is only likely, since GET_SIGNATURES is weaker`() = runTest {
        val probe = FakeSigningInfoProbe(apiLevel = 24, signers = listOf(ATTACKER_KEY))

        assertThat(detect(probe, configPinning(APP_SIGNING_KEY)).single().confidence)
            .isEqualTo(Confidence.LIKELY)
    }

    @Test
    fun `pinning the upload key instead of the app signing key is a mismatch`() = runTest {
        // The failure mode that breaks a real release: with Play App Signing the uploaded
        // artifact and the distributed artifact are signed by different keys.
        val probe = FakeSigningInfoProbe(signers = listOf(APP_SIGNING_KEY))

        assertThat(detect(probe, configPinning(UPLOAD_KEY))).hasSize(1)
    }

    @Test
    fun `any one of several pins is enough`() = runTest {
        val probe = FakeSigningInfoProbe(signers = listOf(APP_SIGNING_KEY))

        assertThat(detect(probe, configPinning(UPLOAD_KEY, APP_SIGNING_KEY))).isEmpty()
    }

    @Test
    fun `multiple signers are reported but do not by themselves mean tampering`() = runTest {
        val probe = FakeSigningInfoProbe(
            signers = listOf(APP_SIGNING_KEY, UPLOAD_KEY),
            multipleSigners = true
        )

        val signals = detect(probe, configPinning(APP_SIGNING_KEY))

        assertThat(signals).isEmpty()
    }

    @Test
    fun `multiple signers are surfaced in evidence on a mismatch`() = runTest {
        val probe = FakeSigningInfoProbe(
            signers = listOf(ATTACKER_KEY, UPLOAD_KEY),
            multipleSigners = true
        )

        val evidence = detect(probe, configPinning(APP_SIGNING_KEY)).single().evidence

        assertThat(evidence["multipleSigners"]).isEqualTo("true")
        assertThat(evidence["signerCount"]).isEqualTo("2")
    }

    @Test
    fun `no configured pin is inconclusive, never clean`() = runTest {
        val signals = detect(FakeSigningInfoProbe(), IntegrityConfig.Builder().build())

        val signal = signals.single()
        assertThat(signal.confidence).isEqualTo(Confidence.INCONCLUSIVE)
        assertThat(signal.evidence["reason"]).isEqualTo("no_pin_configured")
    }

    @Test
    fun `unreadable signing information is inconclusive, never clean`() = runTest {
        val signals = detect(FakeSigningInfoProbe(signers = null), configPinning(APP_SIGNING_KEY))

        assertThat(signals.single().confidence).isEqualTo(Confidence.INCONCLUSIVE)
        assertThat(signals.single().evidence["reason"]).isEqualTo("signing_info_unavailable")
    }

    @Test
    fun `empty signing information is inconclusive, never clean`() = runTest {
        val signals = detect(FakeSigningInfoProbe(signers = emptyList()), configPinning(APP_SIGNING_KEY))

        assertThat(signals.single().confidence).isEqualTo(Confidence.INCONCLUSIVE)
    }

    @Test
    fun `pins are matched case and separator insensitively`() = runTest {
        val probe = FakeSigningInfoProbe(signers = listOf(APP_SIGNING_KEY))
        val config = IntegrityConfig.Builder()
            .expectedSigningCertSha256(APP_SIGNING_KEY.lowercase().chunked(2).joinToString(":"))
            .build()

        assertThat(detect(probe, config)).isEmpty()
    }

    @Test
    fun `evidence carries only a truncated signer digest`() = runTest {
        val evidence = detect(
            FakeSigningInfoProbe(signers = listOf(ATTACKER_KEY)),
            configPinning(APP_SIGNING_KEY)
        ).single().evidence

        assertThat(evidence.getValue("observedSigner")).hasLength(16)
        assertThat(evidence.getValue("observedSigner")).isEqualTo(ATTACKER_KEY.take(16))
    }
}
