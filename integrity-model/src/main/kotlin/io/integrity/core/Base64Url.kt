package io.integrity.core

/**
 * Base64url without padding (RFC 4648 §5).
 *
 * Hand-rolled for the same reason `ReportWire` hand-rolls its JSON and its hex, plus one
 * that is specific to this file: `java.util.Base64` is API 26, and `minSdk` here is 24.
 * Taking the JDK codec would raise the SDK's floor by two API levels to avoid writing
 * forty lines, and `android.util.Base64` is not available to `integrity-model`, which is
 * pure JVM so the backend can share it verbatim.
 *
 * Padding is omitted rather than optional. A codec that accepts both spellings of the same
 * bytes hands an attacker two encodings of one signed payload, and the envelope in
 * [SignedReport] is compared and split as text before anything decodes it.
 */
internal object Base64Url {

    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

    private const val BITS_PER_BYTE = 8
    private const val BITS_PER_CHAR = 6
    private const val CHAR_MASK = 0x3F
    private const val BYTE_MASK = 0xFF

    /** Four base64 characters encode three bytes. */
    private const val CHARS_PER_BLOCK = 4
    private const val BYTES_PER_BLOCK = 3

    /** A one-character trailing group encodes six bits, which no byte string produces. */
    private const val ORPHAN_GROUP = 1

    /** The alphabet is ASCII, so anything above this cannot be in it. */
    private const val ASCII_LIMIT = 128

    /** Reverse table; -1 marks every code point that is not in the alphabet. */
    private val DECODE = IntArray(ASCII_LIMIT) { -1 }.also { table ->
        ALPHABET.forEachIndexed { index, c -> table[c.code] = index }
    }

    fun encode(bytes: ByteArray): String {
        val out = StringBuilder((bytes.size * CHARS_PER_BLOCK + BYTES_PER_BLOCK - 1) / BYTES_PER_BLOCK)
        var buffer = 0
        var bitsHeld = 0
        for (byte in bytes) {
            buffer = (buffer shl BITS_PER_BYTE) or (byte.toInt() and BYTE_MASK)
            bitsHeld += BITS_PER_BYTE
            while (bitsHeld >= BITS_PER_CHAR) {
                bitsHeld -= BITS_PER_CHAR
                out.append(ALPHABET[(buffer shr bitsHeld) and CHAR_MASK])
            }
        }
        // A trailing 2 or 4 bits becomes one more character, left-aligned in its sextet.
        if (bitsHeld > 0) {
            out.append(ALPHABET[(buffer shl (BITS_PER_CHAR - bitsHeld)) and CHAR_MASK])
        }
        return out.toString()
    }

    /**
     * Returns null on anything that is not canonical base64url, rather than throwing or
     * repairing.
     *
     * Rejected: padding, whitespace, alphabet characters from base64's `+/` variant, and a
     * trailing group of one character, which encodes six bits and so cannot have come from
     * any byte string. Every one of those is a second spelling of something, and this codec
     * exists to sit under a signature check where a second spelling is a bypass.
     */
    @Suppress("ReturnCount")
    fun decode(text: String): ByteArray? {
        if (text.isEmpty()) return ByteArray(0)
        if (text.length % CHARS_PER_BLOCK == ORPHAN_GROUP) return null

        val out = ByteArray(text.length * BITS_PER_CHAR / BITS_PER_BYTE)
        var written = 0
        var buffer = 0
        var bitsHeld = 0
        for (c in text) {
            val value = if (c.code < DECODE.size) DECODE[c.code] else -1
            if (value < 0) return null
            buffer = (buffer shl BITS_PER_CHAR) or value
            bitsHeld += BITS_PER_CHAR
            if (bitsHeld >= BITS_PER_BYTE) {
                bitsHeld -= BITS_PER_BYTE
                out[written++] = ((buffer shr bitsHeld) and BYTE_MASK).toByte()
            }
        }
        // The leftover bits are the encoder's left-aligned remainder and must be zero.
        // Non-zero here means two distinct texts decode to the same bytes.
        if (bitsHeld > 0 && (buffer and ((1 shl bitsHeld) - 1)) != 0) return null
        return out.copyOf(written)
    }
}
