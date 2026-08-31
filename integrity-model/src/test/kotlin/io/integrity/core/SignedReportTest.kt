package io.integrity.core

import com.google.common.truth.Truth.assertThat
import kotlin.random.Random
import org.junit.Test

/**
 * The envelope framing and its codec.
 *
 * No cryptography here — that is `ReportVerifierTest` in `sample-backend`, which has real
 * keys. What is pinned here is the framing, which is the part a signature cannot protect:
 * a signature is computed over whatever the framing says the signed bytes are, so an
 * ambiguity in the framing is a hole underneath the signature rather than inside it.
 */
class SignedReportTest {

    private fun header() = SignedReport.Header("key-1", "io.integrity.sample", "0.1.0-alpha01")

    @Test
    fun `sealed envelopes split back into their parts`() {
        val payload = """{"a":1}"""
        val input = SignedReport.signingInput(header(), payload)
        val envelope = SignedReport.seal(input, byteArrayOf(1, 2, 3))

        val parsed = SignedReport.parse(envelope)!!

        assertThat(parsed.header.keyId).isEqualTo("key-1")
        assertThat(parsed.header.packageName).isEqualTo("io.integrity.sample")
        assertThat(parsed.header.sdkVersion).isEqualTo("0.1.0-alpha01")
        assertThat(parsed.canonicalReportJson).isEqualTo(payload)
        assertThat(parsed.signature).isEqualTo(byteArrayOf(1, 2, 3))
    }

    @Test
    fun `the signed bytes are the received prefix, not a re-derivation`() {
        // ADR-0011 §3. If this ever became "rebuild from header and payload", every
        // difference between building and parsing would become a signature bypass.
        val input = SignedReport.signingInput(header(), """{"a":1}""")
        val envelope = SignedReport.seal(input, byteArrayOf(9))

        val parsed = SignedReport.parse(envelope)!!

        assertThat(parsed.signedBytes).isEqualTo(input.bytes)
        assertThat(parsed.signedBytes.decodeToString()).isEqualTo(envelope.substringBeforeLast('.'))
    }

    @Test
    fun `the signed bytes cover the header`() {
        // A header outside the signature would let anyone re-attribute a captured report to
        // a different key id.
        val a = SignedReport.signingInput(header(), """{"a":1}""")
        val other = SignedReport.Header("key-2", "io.integrity.sample", "0.1.0-alpha01")
        val b = SignedReport.signingInput(other, """{"a":1}""")
        assertThat(a.bytes).isNotEqualTo(b.bytes)
    }

    @Test
    fun `rejects envelopes with the wrong shape`() {
        listOf(
            "",
            "IGS1",
            "IGS1.a.b",
            "IGS1.a.b.c.d",
            // Wrong tag: the version is checked before anything is decoded.
            "IGS0.${b64("{}")}.${b64("{}")}.${b64("x")}",
            // Empty signature: an envelope claiming a key it does not substantiate.
            "IGS1.${b64("{}")}.${b64("{}")}."
        ).forEach { assertThat(SignedReport.parse(it)).isNull() }
    }

    @Test
    fun `rejects a header missing a field`() {
        val bad = "IGS1.${b64("""{"keyId":"k","packageName":"p"}""")}.${b64("{}")}.${b64("s")}"
        assertThat(SignedReport.parse(bad)).isNull()
    }

    private fun b64(s: String) = Base64Url.encode(s.encodeToByteArray())

    // --- the codec ------------------------------------------------------------------------

    @Test
    fun `base64url round trips every length up to a few blocks`() {
        val random = Random(seed = 20260831)
        for (length in 0..64) {
            val bytes = random.nextBytes(length)
            assertThat(Base64Url.decode(Base64Url.encode(bytes))).isEqualTo(bytes)
        }
    }

    @Test
    fun `base64url uses the url alphabet and no padding`() {
        // 0xFB 0xFF encodes to "-_" territory in the url alphabet and "+/" in the standard one.
        val encoded = Base64Url.encode(byteArrayOf(0xFB.toByte(), 0xFF.toByte()))
        assertThat(encoded).doesNotContain("+")
        assertThat(encoded).doesNotContain("/")
        assertThat(encoded).doesNotContain("=")
    }

    @Test
    fun `base64url rejects every second spelling`() {
        // Each of these decodes to the same bytes as something else under a lenient codec,
        // which under a signature check means two envelopes with one meaning.
        listOf(
            "AA==", // padding
            "AA=",
            "A", // a lone character encodes six bits and cannot come from any bytes
            "AAAAA",
            "+w", // standard-alphabet characters
            "/w",
            "AA A", // whitespace
            "AA\n",
            "AB" // non-zero trailing bits: "AA" and "AB" would collide
        ).forEach { assertThat(Base64Url.decode(it)).isNull() }
    }

    @Test
    fun `base64url accepts the canonical spelling of a trailing group`() {
        assertThat(Base64Url.decode("AA")).isEqualTo(byteArrayOf(0))
        assertThat(Base64Url.decode("")).isEqualTo(ByteArray(0))
    }
}
