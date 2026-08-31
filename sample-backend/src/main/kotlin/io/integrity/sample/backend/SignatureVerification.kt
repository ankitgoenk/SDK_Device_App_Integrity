package io.integrity.sample.backend

import io.integrity.core.Category
import io.integrity.core.Confidence
import io.integrity.core.Signal
import io.integrity.core.SignalId
import io.integrity.core.SignedReport
import java.security.KeyFactory
import java.security.PublicKey
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

/**
 * Public keys the host has enrolled, looked up by key id.
 *
 * Enrollment happens over the **integrator's** authenticated channel, not ours: they already
 * authenticate the session that carries `sessionId` into a [ReportSubmission], and that
 * authentication is what binds a key to an identity. This project performs no attestation
 * (ADR-0008), so there is nothing else here that could do the binding.
 */
fun interface EnrolledKeys {
    /** The enrolled public key for [keyId], or null if none is enrolled. */
    fun find(keyId: String): PublicKey?
}

/** An in-memory registry. Real deployments back this with the store enrollment writes to. */
class InMemoryEnrolledKeys : EnrolledKeys {
    private val keys = HashMap<String, PublicKey>()

    /** Registers a SubjectPublicKeyInfo-encoded P-256 key. Returns false if it will not parse. */
    fun enrol(keyId: String, encodedPublicKey: ByteArray): Boolean = runCatching {
        keys[keyId] = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(encodedPublicKey))
        true
    }.getOrDefault(false)

    override fun find(keyId: String): PublicKey? = keys[keyId]
}

/**
 * The outcome of checking a submission's envelope.
 *
 * Three cases, and the distinction between the last two is the whole point:
 * [Unsigned] is an integration that has not adopted signing, [Invalid] is a claim of origin
 * that could not be substantiated. Collapsing them would either accuse every host that has
 * not finished integrating, or excuse every forgery that omits its signature.
 */
sealed interface SignatureCheck {

    /** No envelope was presented. Not evidence of anything. */
    data object Unsigned : SignatureCheck

    /** The envelope verified against the enrolled key. Worth nothing — see [ReportVerifier]. */
    data class Valid(val keyId: String, val canonicalReportJson: String) : SignatureCheck

    /**
     * An envelope was presented and did not verify.
     *
     * [canonicalReportJson] is still carried, and is still parsed and scored. A failed
     * signature never discards the evidence that arrived with it — ADR-0011 §2. It is null
     * only when the envelope was too malformed to yield a payload at all.
     */
    data class Invalid(val reason: InvalidReason, val canonicalReportJson: String?) : SignatureCheck
}

/** Why an envelope failed. Diagnostics, and what the mutation suite asserts on. */
enum class InvalidReason {
    MALFORMED_ENVELOPE,
    UNKNOWN_KEY_ID,
    SIGNATURE_MISMATCH
}

/**
 * Checks a signed envelope, and never improves an outcome by doing so.
 *
 * ### Order of operations, which is load-bearing
 *
 * The signature is verified **over the bytes that arrived**, and only then is the payload
 * parsed. The inviting alternative — parse, re-serialise with `ReportWire`, verify the result
 * — is a signature bypass for every input the parser accepts and the serialiser renders
 * differently, and it fails silently for as long as the two happen to agree. ADR-0011 §3.
 *
 * ### The rule this class exists to make structural
 *
 * There is no method here that returns "trusted", "authentic" or a boolean a caller could
 * branch on to permit something. [check] yields evidence or an absence of it, and
 * [signalsFrom] converts only the *failing* case into a [Signal]. A verifier that returned
 * `Boolean` would put `if (verified) allow()` one keystroke away, which is the shape ADR-0007
 * and ADR-0009 have both already had to remove from other types in this project.
 */
class ReportVerifier(private val enrolledKeys: EnrolledKeys) {

    /** Checks [envelope], or reports [SignatureCheck.Unsigned] when there is none. */
    fun check(envelope: String?): SignatureCheck {
        if (envelope == null) return SignatureCheck.Unsigned

        val parsed = SignedReport.parse(envelope)
            ?: return SignatureCheck.Invalid(InvalidReason.MALFORMED_ENVELOPE, null)

        val key = enrolledKeys.find(parsed.header.keyId)
            ?: return SignatureCheck.Invalid(InvalidReason.UNKNOWN_KEY_ID, parsed.canonicalReportJson)

        val verified = runCatching {
            Signature.getInstance(SIGNATURE_ALGORITHM).run {
                initVerify(key)
                update(parsed.signedBytes)
                verify(parsed.signature)
            }
        }.getOrDefault(false)

        return if (verified) {
            SignatureCheck.Valid(parsed.header.keyId, parsed.canonicalReportJson)
        } else {
            SignatureCheck.Invalid(InvalidReason.SIGNATURE_MISMATCH, parsed.canonicalReportJson)
        }
    }

    /**
     * The evidence a check produces, which is a signal on failure and nothing otherwise.
     *
     * Returning a list rather than a nullable signal is not stylistic: it makes "a valid
     * signature contributes nothing" the same shape as "there was no signature", so no caller
     * can accidentally distinguish them. The two cases are indistinguishable downstream by
     * construction, which is exactly ADR-0011 §2's requirement.
     *
     * Confidence is [Confidence.POSSIBLE], not `CONFIRMED`. Key rotation, restored backups and
     * a Keystore cleared by a lock-screen change all land here on honest devices, and every
     * finding this service makes is an accusation (ADR-0008).
     */
    fun signalsFrom(check: SignatureCheck): List<Signal> = when (check) {
        is SignatureCheck.Unsigned, is SignatureCheck.Valid -> emptyList()
        is SignatureCheck.Invalid -> listOf(
            Signal(
                id = SignalId.SRV_REPORT_SIGNATURE_INVALID,
                category = Category.APP_TAMPER,
                confidence = Confidence.POSSIBLE,
                evidence = mapOf("reason" to check.reason.name)
            )
        )
    }

    private companion object {
        const val SIGNATURE_ALGORITHM = "SHA256withECDSA"
    }
}
