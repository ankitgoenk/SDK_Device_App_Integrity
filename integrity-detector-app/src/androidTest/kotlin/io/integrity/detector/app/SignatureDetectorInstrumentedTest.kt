package io.integrity.detector.app

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.integrity.core.Confidence
import io.integrity.core.DetectionContext
import io.integrity.core.IntegrityConfig
import io.integrity.core.SignalId
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The positive and negative controls for signature detection, against a real APK and the
 * real PackageManager rather than a fake probe.
 *
 * These two cases are what "distinguishes clean from compromised" means for this detector:
 * pinning the certificate that genuinely signs this APK must produce nothing, and pinning
 * any other certificate must produce a CONFIRMED mismatch. A repackaged APK reaches the
 * detector as exactly the second case — a pin that does not match the signer — so this
 * covers the same decision path without needing a re-signed artifact.
 */
@RunWith(AndroidJUnit4::class)
class SignatureDetectorInstrumentedTest {

    private val context: Context = ApplicationProvider.getApplicationContext()

    private class RealDetectionContext(override val appContext: Context, override val config: IntegrityConfig) :
        DetectionContext

    private fun detectWithPins(vararg pins: String) = runBlocking {
        val config = IntegrityConfig.Builder().expectedSigningCertSha256(*pins).build()
        SignatureDetector().detect(RealDetectionContext(context, config))
    }

    @Test
    fun theRealSigningCertificateIsReadable() {
        val signers = RealSigningInfoProbe(context).currentSigners()

        assertNotNull("PackageManager returned no signing information", signers)
        assertTrue(signers!!.isNotEmpty())
        // Uppercase hex SHA-256.
        assertEquals(64, signers.first().length)
        assertTrue(signers.first().all { it in "0123456789ABCDEF" })
    }

    /** Negative control: correctly pinned app must produce no signal. */
    @Test
    fun pinningTheActualCertificateProducesNoSignal() {
        val actual = RealSigningInfoProbe(context).currentSigners()!!.first()

        assertTrue(detectWithPins(actual).isEmpty())
    }

    /** Positive control: the state a repackaged, re-signed APK presents. */
    @Test
    fun pinningAnyOtherCertificateIsAConfirmedMismatch() {
        val signals = detectWithPins("00".repeat(32))

        val signal = signals.single()
        assertEquals(SignalId.APP_SIGNATURE_MISMATCH, signal.id)
        assertEquals(Confidence.CONFIRMED, signal.confidence)
    }

    @Test
    fun theLineageCheckAcceptsTheCurrentSigner() {
        val actual = RealSigningInfoProbe(context).currentSigners()!!.first()

        assertTrue(RealSigningInfoProbe(context).matchesLineage(actual))
        assertFalse(RealSigningInfoProbe(context).matchesLineage("00".repeat(32)))
    }

    @Test
    fun evidenceNeverCarriesAPathOrAFullCertificate() {
        val evidence = detectWithPins("00".repeat(32)).single().evidence
        val actual = RealSigningInfoProbe(context).currentSigners()!!.first()

        assertFalse(evidence.values.any { it.contains("/") })
        assertFalse("the full certificate digest must not be reported", evidence.containsValue(actual))
    }
}
