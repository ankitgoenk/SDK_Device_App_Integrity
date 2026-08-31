package io.integrity.core

import android.os.Build
import android.security.keystore.KeyInfo
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.security.KeyFactory
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * On-device fixtures for [KeystoreReportSigner], which has no unit tests and can have none:
 * `AndroidKeyStore` is a device provider, absent from a JVM test JVM.
 *
 * ### The verification here is deliberately not ours
 *
 * Signatures are checked with plain JCE rather than through `sample-backend`'s
 * `ReportVerifier`. Two reasons. `sample-backend` is a JVM module this one must not depend
 * on; and more usefully, an independent oracle cannot agree with the signer by sharing its
 * bug. What is asserted is the same computation `ReportVerifier` performs —
 * `SHA256withECDSA` over [SignedReport.Envelope.signedBytes] — so agreement here is
 * agreement with the backend.
 *
 * ### Every positive result is paired with its negative
 *
 * "The signature verified" proves nothing on its own: a verifier stuck at true satisfies it.
 * So each success is accompanied by the corresponding tamper that must fail, in the same
 * test, against the same key. Hard rule 10.
 */
@RunWith(AndroidJUnit4::class)
class KeystoreReportSignerInstrumentedTest {

    private val alias = "io.integrity.test.report-signing"
    private val otherAlias = "io.integrity.test.report-signing-other"

    private fun keyStore(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    /**
     * Aliases are cleared before *and* after.
     *
     * Before, because a key left behind by a previous run would let
     * [aKeyIsGeneratedOnceAndReused] pass without ever generating anything. After, so the
     * suite leaves no signing key in the app's Keystore.
     */
    @Before
    fun clearAliases() = deleteAliases()

    @After
    fun removeAliases() = deleteAliases()

    private fun deleteAliases() {
        val store = keyStore()
        listOf(alias, otherAlias).forEach { if (store.containsAlias(it)) store.deleteEntry(it) }
    }

    private fun report(challenge: String? = "nonce-1", signals: List<Signal> = emptyList()) = IntegrityReport(
        verdict = Verdict.NO_EVIDENCE_OF_COMPROMISE,
        riskScore = 0,
        categoryScores = emptyMap(),
        signals = signals,
        coverage = 1.0f,
        depth = Depth.STANDARD,
        generatedAtMillis = 1_700_000_000_000L,
        sdkVersion = IntegrityReport.SDK_VERSION,
        reportId = "report-1",
        challenge = challenge
    )

    /** Exactly what `ReportVerifier` computes, with no code shared with the signer. */
    private fun verifies(envelope: SignedReport.Envelope, publicKeyEncoded: ByteArray): Boolean {
        val key = KeyFactory.getInstance("EC")
            .generatePublic(java.security.spec.X509EncodedKeySpec(publicKeyEncoded))
        return Signature.getInstance("SHA256withECDSA").run {
            initVerify(key)
            update(envelope.signedBytes)
            verify(envelope.signature)
        }
    }

    // --- signing, and the tamper that must not verify -------------------------------------

    @Test
    fun aSealedReportVerifiesAndATamperedOneDoesNot() {
        val signer = KeystoreReportSigner(alias)

        val sealed = SignedReports.seal(report(), "io.integrity.core.test", signer)
        assertNotNull("seal() returned null, so the Keystore refused to sign", sealed)

        val parsed = SignedReport.parse(sealed!!)
        assertNotNull("the sealed envelope does not parse; the framing is wrong", parsed)
        assertTrue(
            "a correctly sealed report did not verify against the signer's own public key",
            verifies(parsed!!, signer.publicKeyEncoded())
        )

        // The negative control, without which the assertion above is satisfied by a verifier
        // that always says yes.
        //
        // The tamper splices in the payload of a *differently sealed report* rather than
        // editing base64 characters. An edited character can land on a non-canonical trailing
        // group, which Base64Url rejects outright — the envelope would then fail to parse and
        // the control would silently not run. Substituting a legitimately encoded payload
        // always parses, so this assertion can never be skipped.
        val other = SignedReports.seal(report(challenge = "nonce-2"), "io.integrity.core.test", signer)!!
        val tampered = SignedReport.parse(spliced(sealed, part = 2, from = other))
        assertNotNull("the spliced envelope must still parse, or the control below is skipped", tampered)
        assertNotEquals(
            "the tamper did not change the signed bytes, so it tests nothing",
            String(parsed.signedBytes),
            String(tampered!!.signedBytes)
        )
        assertFalse(
            "a tampered payload verified; the signature is not covering what it must",
            verifies(tampered, signer.publicKeyEncoded())
        )
    }

    /** Replaces one dot-separated part of [envelope] with the same part of [from]. */
    private fun spliced(envelope: String, part: Int, from: String): String {
        val parts = envelope.split(".").toMutableList()
        parts[part] = from.split(".")[part]
        return parts.joinToString(".")
    }

    @Test
    fun theHeaderCarriesTheKeyIdAndPackageAndIsCoveredByTheSignature() {
        val signer = KeystoreReportSigner(alias)
        val sealed = SignedReports.seal(report(), "io.integrity.core.test", signer)!!
        val parsed = SignedReport.parse(sealed)!!

        assertEquals(signer.keyId, parsed.header.keyId)
        assertEquals("io.integrity.core.test", parsed.header.packageName)
        assertEquals(IntegrityReport.SDK_VERSION, parsed.header.sdkVersion)

        // Re-attributing a captured report to another header must break the signature.
        // Same reasoning as above: the substituted header is a real encoding, so the parse
        // cannot fail and let this control be skipped.
        val otherHeader = SignedReports.seal(report(), "io.integrity.other.package", signer)!!
        val swapped = SignedReport.parse(spliced(sealed, part = 1, from = otherHeader))
        assertNotNull("the spliced envelope must still parse", swapped)
        assertEquals("io.integrity.other.package", swapped!!.header.packageName)
        assertFalse(
            "a swapped header verified, so the header is outside the signature",
            verifies(swapped, signer.publicKeyEncoded())
        )
    }

    @Test
    fun theChallengeInsideTheReportIsWhatGetsSigned() {
        // ADR-0006 §6: the nonce is bound where the evidence is gathered. If it were not
        // inside the signed payload, a captured signature would answer any challenge.
        val signer = KeystoreReportSigner(alias)
        val first = SignedReport.parse(SignedReports.seal(report("nonce-1"), "p", signer)!!)!!
        val second = SignedReport.parse(SignedReports.seal(report("nonce-2"), "p", signer)!!)!!

        assertNotEquals(String(first.signedBytes), String(second.signedBytes))
        assertTrue(first.canonicalReportJson.contains("nonce-1"))
        assertFalse(first.canonicalReportJson.contains("nonce-2"))
    }

    // --- key lifecycle ---------------------------------------------------------------------

    @Test
    fun aKeyIsGeneratedOnceAndReused() {
        assertFalse("the alias was not clean before the test", keyStore().containsAlias(alias))

        val first = KeystoreReportSigner(alias)
        val keyId = first.keyId
        assertTrue("no key was generated on first use", keyStore().containsAlias(alias))

        // A second instance over the same alias must adopt the existing key, not mint a new
        // one — otherwise every sweep would invalidate the enrollment the host performed.
        val second = KeystoreReportSigner(alias)
        assertEquals(keyId, second.keyId)
        assertTrue(first.publicKeyEncoded().contentEquals(second.publicKeyEncoded()))

        val sealed = SignedReport.parse(SignedReports.seal(report(), "p", second)!!)!!
        assertTrue(
            "a report signed by the second instance did not verify against the first's key",
            verifies(sealed, first.publicKeyEncoded())
        )
    }

    @Test
    fun differentAliasesGetDifferentKeysAndDifferentKeyIds() {
        val a = KeystoreReportSigner(alias)
        val b = KeystoreReportSigner(otherAlias)

        assertNotEquals("the key id is not derived from the key", a.keyId, b.keyId)

        // And a signature from one must not verify under the other, which is the property
        // the differing ids are supposed to represent.
        val sealed = SignedReport.parse(SignedReports.seal(report(), "p", a)!!)!!
        assertFalse(sealed.signature.isEmpty())
        assertFalse(
            "a signature verified under the wrong key",
            verifies(sealed, b.publicKeyEncoded())
        )
    }

    @Test
    fun theKeyIdIsADigestOfThePublicKeyRatherThanAStoredLabel() {
        val signer = KeystoreReportSigner(alias)
        val recomputed = KeystoreReportSigner.keyIdOf(
            KeyFactory.getInstance("EC")
                .generatePublic(java.security.spec.X509EncodedKeySpec(signer.publicKeyEncoded()))
        )
        // The backend recomputes the id from the key it holds; if these diverged, an enrolled
        // key could never be found for the id a client presents.
        assertEquals(signer.keyId, recomputed)
    }

    // --- the property ADR-0011 actually relies on ------------------------------------------

    @Test
    fun thePrivateKeyIsNotExportable() {
        // This is the whole difference from the HMAC scheme ADR-0011 rejected. If the private
        // key could be read out, compromise would be per-build again rather than per-device.
        // Touching keyId is what generates the key; the alias is empty until it does.
        KeystoreReportSigner(alias).keyId

        val key = keyStore().getKey(alias, null) as PrivateKey
        assertNull(
            "the private key was exportable, which is the property this scheme depends on",
            key.encoded
        )
    }

    @Test
    fun hardwareBackingIsReportedButNeverRequired() {
        // ADR-0008 and hard rule 9: establishing that a key lives in a TEE is attestation,
        // and it would be an input raising confidence in a device. So this asserts only that
        // signing works either way, and prints what it got. An emulator has no TEE, and this
        // test must pass there — a test that required hardware backing would be asserting
        // the thing the ADR says we must not check.
        val signer = KeystoreReportSigner(alias)
        // Generation is lazy: touch keyId first, or the alias is still empty below.
        signer.keyId
        val key = keyStore().getKey(alias, null) as PrivateKey

        val backing = runCatching {
            val info = KeyFactory.getInstance(key.algorithm, "AndroidKeyStore")
                .getKeySpec(key, KeyInfo::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                "securityLevel=${info.securityLevel}"
            } else {
                @Suppress("DEPRECATION")
                "insideSecureHardware=${info.isInsideSecureHardware}"
            }
        }.getOrElse { "unknown (${it.javaClass.simpleName})" }
        println("KeystoreReportSigner key backing: $backing")

        assertNotNull("signing must work regardless of backing", SignedReports.seal(report(), "p", signer))
    }
}
