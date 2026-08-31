package io.integrity.core

/**
 * The signed envelope a report travels in, and the bytes a signature is computed over.
 *
 * Lives in `integrity-model` so the backend uses *this* code to split and verify what the
 * client used to assemble — the same reason the scoring model is shared rather than
 * reimplemented. Two implementations of a framing convention is a way of eventually
 * discovering that they disagree, and here the disagreement would be a signature bypass.
 *
 * ### Shape
 *
 * ```
 * IGS1.<b64url(header)>.<b64url(canonicalReport)>.<b64url(signature)>
 * ```
 *
 * JWS-shaped, and for the reason JWS has that shape: base64url contains no `.`, so the
 * framing needs no length prefixes and no escaping, and no input can move a separator.
 * The alternative — concatenating fields to sign them — has the classic ambiguity where
 * `"ab" ‖ "c"` and `"a" ‖ "bc"` produce identical signing input.
 *
 * The signature covers everything before the final separator, so the header is signed with
 * the payload. A header outside the signature would let anyone swap the `keyId` on a
 * captured report and have it verified against a different key.
 *
 * ### What is deliberately not in here
 *
 * The **nonce**. `challenge` is inside the canonical report already, put there by ADR-0006 §6
 * so that it could not be attached to evidence gathered before it was issued. Repeating it in
 * the header would create a second copy, and two copies can disagree — at which point some
 * code has to choose which one is the real binding, and that choice is the vulnerability.
 *
 * See ADR-0011.
 */
public object SignedReport {

    /**
     * Format tag, and the first thing checked.
     *
     * Bumped if the framing or the signed-input construction changes. Not the same number as
     * [ReportWire.WIRE_VERSION], which versions the payload: the envelope and its contents
     * change for unrelated reasons, and one version field for two schemas means neither can
     * move without lying about the other.
     */
    public const val ENVELOPE_TAG: String = "IGS1"

    private const val SEPARATOR = '.'
    private const val PART_COUNT = 4
    private const val TAG_PART = 0
    private const val HEADER_PART = 1
    private const val REPORT_PART = 2
    private const val SIGNATURE_PART = 3

    /**
     * Signing metadata, canonicalised into the envelope header.
     *
     * [packageName] is here rather than in the report because it is not part of the
     * evidence: it says which app produced the report, which the backend needs in order to
     * know whether the enrolled key it is about to check belongs to the app it expects.
     */
    public class Header(public val keyId: String, public val packageName: String, public val sdkVersion: String) {
        internal fun canonicalJson(): String = """{"keyId":${jsonString(keyId)},""" +
            """"packageName":${jsonString(packageName)},""" +
            """"sdkVersion":${jsonString(sdkVersion)}}"""

        override fun toString(): String = "Header($keyId, $packageName, $sdkVersion)"
    }

    /**
     * A parsed envelope, still unverified.
     *
     * [signedBytes] is retained as the exact bytes that were received, never rebuilt from
     * [header] and [canonicalReportJson]. Re-deriving it would reintroduce the parse-then-
     * re-serialise hazard that ADR-0011 §3 exists to close: the signature must be checked
     * against what arrived, not against what a round trip produces from it.
     */
    public class Envelope internal constructor(
        public val header: Header,
        public val canonicalReportJson: String,
        public val signature: ByteArray,
        public val signedBytes: ByteArray
    )

    /**
     * Assembles the signing input for a report that has not been signed yet.
     *
     * Returns the bytes to sign together with the two encoded parts, so the caller can build
     * the finished envelope with [seal] without re-encoding anything. Encoding twice and
     * assuming the results match is how the signed bytes and the transmitted bytes drift
     * apart.
     */
    public fun signingInput(header: Header, canonicalReportJson: String): SigningInput {
        val encodedHeader = Base64Url.encode(header.canonicalJson().encodeToByteArray())
        val encodedReport = Base64Url.encode(canonicalReportJson.encodeToByteArray())
        val prefix = "$ENVELOPE_TAG$SEPARATOR$encodedHeader$SEPARATOR$encodedReport"
        return SigningInput(prefix, prefix.encodeToByteArray())
    }

    /** The bytes to sign, and the envelope prefix they came from. */
    public class SigningInput internal constructor(internal val prefix: String, public val bytes: ByteArray)

    /** Completes an envelope by appending a signature over [input]. */
    public fun seal(input: SigningInput, signature: ByteArray): String =
        "${input.prefix}$SEPARATOR${Base64Url.encode(signature)}"

    /**
     * Splits an envelope without verifying it.
     *
     * Returns null on anything malformed. Deliberately total rather than throwing: this runs
     * on the first bytes of an untrusted submission, where an exception type is one more
     * thing that can leak into a response, and where "malformed" and "does not verify" should
     * converge on the same handling rather than two.
     */
    @Suppress("ReturnCount")
    public fun parse(envelope: String): Envelope? {
        val parts = envelope.split(SEPARATOR)
        if (parts.size != PART_COUNT) return null
        if (parts[TAG_PART] != ENVELOPE_TAG) return null

        val headerBytes = Base64Url.decode(parts[HEADER_PART]) ?: return null
        val reportBytes = Base64Url.decode(parts[REPORT_PART]) ?: return null
        val signature = Base64Url.decode(parts[SIGNATURE_PART]) ?: return null
        if (signature.isEmpty()) return null

        val header = parseHeader(headerBytes.decodeToString()) ?: return null

        return Envelope(
            header = header,
            canonicalReportJson = reportBytes.decodeToString(),
            signature = signature,
            // Exactly the received prefix, character for character. See [Envelope].
            signedBytes = "${parts[TAG_PART]}$SEPARATOR${parts[HEADER_PART]}$SEPARATOR${parts[REPORT_PART]}"
                .encodeToByteArray()
        )
    }

    /** Every field is required; a header missing one names a key it cannot describe. */
    private fun parseHeader(json: String): Header? {
        val fields = JsonReader.readFlatObject(json) ?: return null
        val keyId = fields["keyId"]
        val packageName = fields["packageName"]
        val sdkVersion = fields["sdkVersion"]
        return if (keyId == null || packageName == null || sdkVersion == null) {
            null
        } else {
            Header(keyId, packageName, sdkVersion)
        }
    }

    private fun jsonString(value: String): String = JsonWriter.string(value)
}
