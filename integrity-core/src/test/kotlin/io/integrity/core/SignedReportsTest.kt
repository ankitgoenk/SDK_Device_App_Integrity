package io.integrity.core

import com.google.common.truth.Truth.assertThat
import java.security.ProviderException
import org.junit.Test

/**
 * [SignedReports.seal] against signers that fail, which needs no device.
 *
 * `SERVER_VERIFICATION.md` says "`KeystoreReportSigner` has no unit tests and can have none —
 * `AndroidKeyStore` is a device provider". True of the *signer*. It got extended, without anyone
 * noticing, to the thing sitting on top of it: `seal` takes the [ReportSigner] **interface**, so
 * every failure mode is reachable from a fake in three lines.
 *
 * The one that mattered is [a signer that cannot produce a key id]. `seal` guarded
 * `signer.sign(...)` and read `signer.keyId` on the line before it — and `keyId` is where
 * `KeystoreReportSigner` generates the key, so it is where an ordinary Keystore failure lands.
 */
class SignedReportsTest {

    private val report = IntegrityReport.unknown(Depth.FULL)

    private class Fake(
        private val id: String = "key-1",
        private val signature: ByteArray? = ByteArray(8) { it.toByte() },
        private val throwFromKeyId: Boolean = false,
        private val throwFromSign: Boolean = false
    ) : ReportSigner {
        var signCalled: Boolean = false
            private set

        override val keyId: String
            // ProviderException rather than something generic: it is what a wedged keymaster
            // actually throws out of `generateKeyPair`, which is the failure this covers.
            get() = if (throwFromKeyId) throw ProviderException("failed to generate key pair") else id

        override fun sign(signingInput: ByteArray): ByteArray? {
            signCalled = true
            if (throwFromSign) throw ProviderException("keymaster refused")
            return signature
        }
    }

    @Test
    fun `seals an envelope a signer can produce`() {
        // The positive direction first: without it every assertion below passes against a
        // `seal` that returned null for everything.
        val sealed = SignedReports.seal(report, "io.integrity.sample", Fake())

        assertThat(sealed).isNotNull()
        val parsed = SignedReport.parse(sealed!!)
        assertThat(parsed).isNotNull()
        assertThat(parsed!!.header.keyId).isEqualTo("key-1")
        assertThat(parsed.header.packageName).isEqualTo("io.integrity.sample")
        assertThat(parsed.header.sdkVersion).isEqualTo(report.sdkVersion)
    }

    @Test
    fun `returns null when the signer declines to sign`() {
        assertThat(SignedReports.seal(report, "p", Fake(signature = null))).isNull()
    }

    @Test
    fun `returns null when the signer throws from sign`() {
        assertThat(SignedReports.seal(report, "p", Fake(throwFromSign = true))).isNull()
    }

    @Test
    fun `returns null when the signer cannot produce a key id`() {
        // The regression. `keyId` is read before the guarded call, so this used to propagate
        // out of the SDK into the host: hard rule 5, and the failure `SERVER_VERIFICATION.md`
        // then reads as COMPROMISED, on an honest device whose Keystore had a bad day.
        val signer = Fake(throwFromKeyId = true)

        assertThat(SignedReports.seal(report, "p", signer)).isNull()
        // And it failed before signing, rather than after — which is what makes this a
        // different code path from the case above rather than the same one twice.
        assertThat(signer.signCalled).isFalse()
    }

    @Test
    fun `an empty signature is refused rather than sealed`() {
        // An envelope presenting a keyId it cannot substantiate is exactly the shape the
        // backend raises SRV_REPORT_SIGNATURE_INVALID for, so producing one would manufacture
        // evidence against an honest device — which is what the KDoc says and what an empty
        // ByteArray, not being null, used to slip past.
        assertThat(SignedReports.seal(report, "p", Fake(signature = ByteArray(0)))).isNull()
    }
}
