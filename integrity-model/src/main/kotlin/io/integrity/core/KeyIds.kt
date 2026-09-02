package io.integrity.core

import java.security.MessageDigest
import java.security.PublicKey

/**
 * How a report-signing key is named: a digest of the key, never a label chosen alongside it.
 *
 * ### Why this lives in `integrity-model`
 *
 * `KeystoreReportSigner.keyIdOf` said, of a derived key id, that it exists "so a client cannot
 * claim one key id while holding another: **the backend recomputes it from the key it has
 * enrolled and compares**".
 *
 * The backend could not. `keyIdOf` was in `integrity-core`, an Android library, and
 * `ARCHITECTURE.md` records why the backend cannot depend on one: "a JVM backend cannot consume
 * an AAR". So the sentence described a step that was architecturally unavailable to the party it
 * named — and the split-package choice made that invisible, since `io.integrity.core.SignedReport`
 * (reachable) and `io.integrity.core.KeystoreReportSigner` (not) read identically in an import
 * list. That cost is acknowledged in `ARCHITECTURE.md`; this is it cashing in.
 *
 * Same argument as [DexAggregate], with the parties substituted: the client and the backend must
 * derive this identically or the comparison is meaningless, and a copy in each is how they come
 * to disagree. There were three copies — `KeystoreReportSigner`, `ReportVerifierTest`, and the
 * recomputation the backend never performed — agreeing by nobody's design.
 *
 * ### What deriving it does and does not buy
 *
 * Not forgery resistance: claiming somebody else's key id makes the signature verify against
 * *their* public key, which fails. What it buys is that the id cannot be chosen. Nothing here
 * relies on 128 bits being hard to collide; it relies on an id nobody gets to pick, which is a
 * property an unvalidated `enrol(keyId, key)` parameter destroyed outright — an attacker wanting
 * another user's slot does not need a SHA-256 collision if they can type the string.
 */
public object KeyIds {

    /** 16 bytes of a SHA-256. Collision risk is negligible and the envelope header stays short. */
    private const val KEY_ID_BYTES = 16

    private const val BITS_PER_NIBBLE = 4
    private const val NIBBLE_MASK = 0xF
    private const val BYTE_MASK = 0xFF
    private const val HEX = "0123456789abcdef"

    /** The id for a parsed key. */
    public fun of(publicKey: PublicKey): String = of(publicKey.encoded)

    /**
     * The id for SubjectPublicKeyInfo bytes, which is the form enrolment receives.
     *
     * Taking bytes rather than only a [PublicKey] is what lets an enrolment endpoint derive the
     * id from what it was given instead of accepting one alongside it.
     */
    public fun of(encodedPublicKey: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(encodedPublicKey)
        // Hand-rolled rather than `"%02x".format`, for the reason `JsonWriter` gives about its
        // own hex: `String.format` renders through the default locale, and an identifier
        // compared across two machines must not contain a single locale-dependent rendering.
        val out = StringBuilder(KEY_ID_BYTES * 2)
        for (index in 0 until minOf(KEY_ID_BYTES, digest.size)) {
            val byte = digest[index].toInt() and BYTE_MASK
            out.append(HEX[byte shr BITS_PER_NIBBLE]).append(HEX[byte and NIBBLE_MASK])
        }
        return out.toString()
    }
}
