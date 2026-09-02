package io.integrity.core

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/**
 * Signs the canonical bytes of a report. See ADR-0011.
 *
 * ### What a signature is for here, and what it is not for
 *
 * It makes a report **expensive to forge off the device**. It does nothing about a report
 * that is honestly signed and dishonestly assembled: on a rooted device the Keystore signs
 * whatever it is asked to, so a fabricated report gets a perfect signature. And it does
 * nothing about silence — the ADR-0007 hole, where a client suppresses every signal and
 * signs the resulting empty report correctly, is untouched.
 *
 * The backend consequently treats a valid signature as worth **nothing**: it is not a route
 * to a better outcome, and no code path grants one. Only the *failure* of a signature that
 * was claimed is evidence, and it can only point one way. That asymmetry is the whole design,
 * and a signer implementation cannot affect it.
 */
public interface ReportSigner {

    /**
     * Identifies the public key the backend should check against.
     *
     * The host enrols this over its own authenticated channel; this SDK originates no network
     * traffic (ADR-0003) and so cannot enrol anything itself.
     *
     * **Note the asymmetry with [sign], and where it is contained.** [sign] returns null when it
     * cannot produce a signature; this property has no such channel, so an implementation that
     * cannot produce a key id has nothing to do but throw. [SignedReports.seal] therefore catches
     * around *both*, which is what makes the contract hold for implementations this module will
     * never see. Widening this to `String?` would express the failure instead of containing it —
     * a source-breaking change to a public SPI, worth taking while there is no public release,
     * and deliberately not bundled with the containment fix.
     */
    public val keyId: String

    /** The signature over [signingInput], or null if signing was not possible. */
    public fun sign(signingInput: ByteArray): ByteArray?
}

/**
 * Wraps a report in its signed envelope.
 *
 * Separate from [IntegrityGuard] because signing is not part of evaluating: a host may
 * evaluate without ever signing, and one that signs does so at the moment it transports,
 * which it owns. Folding this into the guard would put a key operation on the detection path.
 */
public object SignedReports {

    /**
     * Returns the envelope, or null when [signer] could not produce one. Never throws.
     *
     * Null is returned rather than an unsigned envelope. An envelope with an empty signature
     * would present a `keyId` it cannot substantiate, which is precisely the shape the
     * backend raises `SRV_REPORT_SIGNATURE_INVALID` for — so a signing failure on an honest
     * device would manufacture evidence against it. A host that cannot sign should send the
     * canonical report unsigned, which the backend accepts without accusation.
     *
     * ### Why the whole body is wrapped, and not just the signing call
     *
     * That reasoning had a hole. The guard used to sit on `signer.sign(...)`, and the *first*
     * statement was `signer.keyId` — which in [KeystoreReportSigner] is the property that
     * generates the key. Every ordinary Keystore failure surfaces there rather than in `sign`:
     * `generateKeyPair` throwing `ProviderException` on a wedged keymaster, a missing provider,
     * a null certificate for an alias that exists. Those propagated out of an SDK embedded in
     * someone else's app, which hard rule 5 forbids and `IntegrityGuard` calls "worse than no
     * integrity SDK".
     *
     * The consequence was the one this doc set out to prevent, reached by another route: no
     * envelope, so no report, and `SERVER_VERIFICATION.md` reads "no report at all" as
     * `COMPROMISED` for high-value actions. A keystore hiccup on an honest phone ended at an
     * accusation.
     *
     * Wrapping here rather than inside [KeystoreReportSigner] is deliberate: it holds for any
     * [ReportSigner], including ones this module will never see, and the SPI gives an
     * implementation no way to decline a `keyId` other than throwing.
     */
    public fun seal(report: IntegrityReport, packageName: String, signer: ReportSigner): String? =
        runCatching {
            val header = SignedReport.Header(
                keyId = signer.keyId,
                packageName = packageName,
                sdkVersion = report.sdkVersion
            )
            val input = SignedReport.signingInput(header, ReportWire.canonicalJson(report))
            // `takeIf { it.isNotEmpty() }`, because an empty ByteArray is not null and this
            // doc's whole point is that an envelope with an empty signature must not exist:
            // it presents a `keyId` it cannot substantiate. Sealing one produced an envelope
            // `SignedReport.parse` rejects, which is a malformed submission rather than the
            // unsigned one a host that cannot sign should be sending.
            val signature = signer.sign(input.bytes)?.takeIf { it.isNotEmpty() }
                ?: return@runCatching null
            SignedReport.seal(input, signature)
        }.getOrNull()
}

/**
 * ECDSA P-256 with a non-exportable key in the Android Keystore.
 *
 * Hardware-backed where the device provides it, but **nothing here checks whether it is**,
 * and the backend is given no way to ask. Establishing that a key lives in a TEE is key
 * attestation, which is attestation, which ADR-0008 put outside this project — and it would
 * be an input that raised confidence in a device, which hard rule 9 forbids outright. So the
 * property being relied on is only the one available without asking Google anything: the
 * private key cannot be read out of the Keystore, so a compromise is per-device rather than
 * per-build.
 *
 * That is a real difference from the HMAC scheme `SERVER_VERIFICATION.md` used to offer as a
 * fallback, whose key is identical in every install and forges for everyone once extracted.
 *
 * Key generation is lazy and idempotent: the first [sign] creates the keypair if the alias is
 * empty, and every later call reuses it. The host enrols [publicKeyEncoded] once, over its own
 * authenticated session.
 */
public class KeystoreReportSigner(private val alias: String = DEFAULT_ALIAS) : ReportSigner {

    // Lazy, so constructing a signer cannot throw. `KeyStore.load` declares IOException,
    // NoSuchAlgorithmException and CertificateException, and a constructor that throws is a
    // failure a host cannot contain by checking the result.
    private val keyStore: KeyStore by lazy {
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    }

    override val keyId: String
        get() = keyIdOf(publicKey())

    /**
     * The SubjectPublicKeyInfo bytes to enrol with the backend.
     *
     * Public by definition, so shipping it carries no secret. It is still a **stable
     * per-install identifier**, and that is a cost the scheme cannot avoid: a backend that
     * must find the right key to check has to be told which one. It stays in the envelope
     * header and never enters signal evidence, so hard rule 3's boundary — no device
     * identity inside the evidence — holds. See ADR-0011's consequences.
     *
     * **Throws if the Keystore cannot produce a key**, and is not contained the way
     * [SignedReports.seal] is. That is the right shape here: enrolment is a host-driven step
     * with a user present, where a failure is worth surfacing and retrying rather than
     * silently skipping. Detection and signing are the paths that must never throw.
     */
    public fun publicKeyEncoded(): ByteArray = publicKey().encoded

    override fun sign(signingInput: ByteArray): ByteArray? = runCatching {
        Signature.getInstance(SIGNATURE_ALGORITHM).run {
            initSign(privateKey())
            update(signingInput)
            sign()
        }
    }.getOrNull()

    // `ensureKey()` returns Unit, so the `.let` these two used to be written with was
    // decoration that hid a second statement running after it.
    private fun publicKey(): PublicKey {
        ensureKey()
        // getCertificate returns null for an alias that holds no certificate — reachable if
        // the entry was created or removed by something else. Dereferencing it was an NPE.
        val certificate = keyStore.getCertificate(alias)
            ?: error("Keystore alias '$alias' holds no certificate after key generation")
        return certificate.publicKey
    }

    private fun privateKey(): PrivateKey {
        ensureKey()
        return keyStore.getKey(alias, null) as? PrivateKey
            ?: error("Keystore alias '$alias' holds no private key after key generation")
    }

    private fun ensureKey() {
        if (keyStore.containsAlias(alias)) return
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE).apply {
            initialize(
                KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(ECGenParameterSpec(CURVE))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    // Deliberately not setUserAuthenticationRequired: a report is signed on a
                    // background sweep, with no user present to authenticate, and a key that
                    // demanded it would simply never sign.
                    .build()
            )
        }.generateKeyPair()
    }

    public companion object {
        public const val DEFAULT_ALIAS: String = "io.integrity.report-signing"

        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val SIGNATURE_ALGORITHM = "SHA256withECDSA"
        private const val CURVE = "secp256r1"

        /**
         * A key id is a digest of the public key, not a random label.
         *
         * Derived rather than stored, so it cannot drift from the key it names, and so a
         * client cannot claim one key id while holding another: the backend recomputes it
         * from the key it has enrolled and compares.
         */
        public fun keyIdOf(publicKey: PublicKey): String {
            val digest = MessageDigest.getInstance("SHA-256").digest(publicKey.encoded)
            return digest.toHexString(KEY_ID_BYTES)
        }

        /** 16 bytes of a SHA-256. Collision risk is negligible and the header stays short. */
        private const val KEY_ID_BYTES = 16

        private const val BITS_PER_NIBBLE = 4
        private const val NIBBLE_MASK = 0xF
        private const val BYTE_MASK = 0xFF

        private fun ByteArray.toHexString(limit: Int): String {
            val hex = "0123456789abcdef"
            val out = StringBuilder(limit * 2)
            for (i in 0 until minOf(limit, size)) {
                val b = this[i].toInt() and BYTE_MASK
                out.append(hex[b shr BITS_PER_NIBBLE]).append(hex[b and NIBBLE_MASK])
            }
            return out.toString()
        }
    }
}
