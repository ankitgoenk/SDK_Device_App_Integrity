package io.integrity.sample.backend

import java.security.MessageDigest
import java.util.Base64

/**
 * The outcome of checking a Play Integrity token.
 *
 * Three cases rather than a boolean, because "we could not check" and "we checked and it is
 * bad" must not collapse. A verifier that cannot reach Google returns [Unavailable], and the
 * pipeline turns that into [DeviceState.UNAVAILABLE] — never into a pass.
 */
sealed interface AttestationOutcome {

    data class Verified(
        val appRecognised: Boolean,
        val deviceRecognised: Boolean,
        /** The requestHash Google echoes back, which must match the challenge we minted. */
        val requestHash: String?
    ) : AttestationOutcome

    /** Transient: network, quota, Play Services. Not evidence of anything about the device. */
    data object Unavailable : AttestationOutcome

    /** The token did not verify. Evidence, and bad. */
    data class Invalid(val reason: String) : AttestationOutcome
}

/**
 * Verifies a Play Integrity token.
 *
 * The SDK never does this (ADR-0006): a client grading Google's answer about itself is the
 * circularity this architecture removes. Verification is the authoritative step and belongs
 * entirely to the backend.
 */
fun interface PlayIntegrityVerifier {
    fun verify(token: String): AttestationOutcome
}

/**
 * Marks a verifier that does **not** talk to Google.
 *
 * Every fixture in this repository carries it, and [VerificationService.forProduction] refuses
 * to construct a service around one. Without an enforced marker, "Play Integrity is behind an
 * interface" is a sentence in a design document, and the way it fails is that a stub ships.
 *
 * Nothing in this repository verifies Google's cryptographic attestation. The tests prove
 * binding, freshness, replay protection and server-side scoring against deterministic
 * fixtures; they say nothing whatsoever about whether a real token is genuine. That requires
 * the actual integration and credentials, and until it exists this boundary is the honest
 * statement of what is and is not established.
 */
interface NotForProduction

/**
 * Derives the `requestHash` the app must pass to Play Integrity for a given challenge.
 *
 * This is the protocol coupling ADR-0006 wants: the same nonce goes into Google's token and is
 * echoed in our report, so the two halves cannot be mixed and matched from different sessions.
 */
object RequestHash {

    fun of(challenge: String): String = Base64.getUrlEncoder().withoutPadding().encodeToString(
        MessageDigest.getInstance("SHA-256").digest(challenge.toByteArray(Charsets.UTF_8))
    )

    /**
     * Constant-time comparison. The values are not secret, but the habit is worth keeping and
     * the cost is nil; a length-dependent early exit here would be the kind of detail nobody
     * revisits once it is copied into somewhere it matters.
     */
    fun matches(expected: String, actual: String?): Boolean {
        if (actual == null || actual.length != expected.length) return false
        var difference = 0
        for (index in expected.indices) {
            difference = difference or (expected[index].code xor actual[index].code)
        }
        return difference == 0
    }
}
