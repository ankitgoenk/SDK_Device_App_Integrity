package io.integrity.core

/**
 * The escaping half of the canonical form, extracted so the parser and the serialiser cannot
 * drift apart. [ReportWire] delegates here; its round-trip tests pin the bytes.
 */
internal object JsonWriter {

    private const val BITS_PER_NIBBLE = 4
    private const val NIBBLES_PER_ESCAPE = 4
    private const val NIBBLE_MASK = 0xF
    private val HEX_DIGITS = "0123456789abcdef".toCharArray()

    /** Minimal, deterministic JSON string escaping. */
    fun string(value: String): String {
        val out = StringBuilder(value.length + 2)
        out.append('"')
        for (c in value) {
            when {
                c == '"' -> out.append("\\\"")
                c == '\\' -> out.append("\\\\")
                c == '\n' -> out.append("\\n")
                c == '\r' -> out.append("\\r")
                c == '\t' -> out.append("\\t")
                // Everything below 0x20 must be escaped, and \\u is the only form that is
                // unambiguous across the whole range.
                c < ' ' -> appendUnicodeEscape(out, c.code)
                else -> out.append(c)
            }
        }
        out.append('"')
        return out.toString()
    }

    /**
     * Hand-rolled hex, because `String.format` uses the default locale.
     *
     * A canonical form must not contain a single locale-dependent rendering. Writing the
     * nibbles directly removes the question rather than answering it with `Locale.ROOT`.
     */
    private fun appendUnicodeEscape(out: StringBuilder, code: Int) {
        out.append("\\u")
        // Most significant nibble first, so 0x1f renders as 001f rather than f100.
        for (position in NIBBLES_PER_ESCAPE - 1 downTo 0) {
            out.append(HEX_DIGITS[(code shr (position * BITS_PER_NIBBLE)) and NIBBLE_MASK])
        }
    }
}

/** A value in the canonical form. There are no floats and no booleans; see [JsonReader]. */
internal sealed interface JsonValue {
    class Obj(val fields: Map<String, JsonValue>) : JsonValue
    class Arr(val items: List<JsonValue>) : JsonValue
    class Str(val value: String) : JsonValue
    class Num(val value: Long) : JsonValue
    object Null : JsonValue
}

/**
 * A strict reader for the canonical form, and nothing wider.
 *
 * The governing rule is that **this parser accepts exactly what [ReportWire] emits**. That is
 * a stronger requirement than "parses the report correctly", and it is the requirement that
 * matters: under a signature check, every input a parser accepts but a serialiser would never
 * produce is a payload whose meaning is decided here and nowhere else. So it rejects
 * insignificant whitespace, duplicate keys, floats, exponents, `true`/`false`, leading zeros,
 * `+1`, `-0`, and trailing content after the top-level value — none of which the canonical
 * form contains.
 *
 * Duplicate keys deserve their own note, because a permissive parser's choice of last-wins or
 * first-wins is the classic way two components read one signed document differently.
 * Rejecting outright means there is no choice to disagree about.
 *
 * Total, never throwing: a malformed submission is an ordinary outcome on this path, not an
 * exceptional one. Every failure returns null.
 */
@Suppress("ReturnCount", "TooManyFunctions")
internal object JsonReader {

    /** Parses a whole document, or null. */
    fun read(text: String): JsonValue? {
        val cursor = Cursor(text)
        val value = cursor.readValue() ?: return null
        // Trailing bytes are not "ignored suffix" here; they are a second document smuggled
        // inside the signed one.
        if (!cursor.atEnd()) return null
        return value
    }

    /** Convenience for the envelope header: an object whose every value is a string. */
    fun readFlatObject(text: String): Map<String, String>? {
        val root = read(text) as? JsonValue.Obj ?: return null
        val out = LinkedHashMap<String, String>(root.fields.size)
        for ((key, value) in root.fields) {
            val str = value as? JsonValue.Str ?: return null
            out[key] = str.value
        }
        return out
    }

    private class Cursor(private val text: String) {
        private var at = 0

        fun atEnd(): Boolean = at >= text.length

        private fun peek(): Char? = if (at < text.length) text[at] else null

        private fun take(expected: Char): Boolean {
            if (peek() != expected) return false
            at++
            return true
        }

        fun readValue(): JsonValue? = when (peek()) {
            '{' -> readObject()
            '[' -> readArray()
            '"' -> readString()?.let { JsonValue.Str(it) }
            'n' -> readNull()
            else -> readNumber()
        }

        private fun readNull(): JsonValue? {
            if (!text.startsWith("null", at)) return null
            at += "null".length
            return JsonValue.Null
        }

        private fun readObject(): JsonValue? {
            if (!take('{')) return null
            val fields = LinkedHashMap<String, JsonValue>()
            if (take('}')) return JsonValue.Obj(fields)
            while (true) {
                val key = readString() ?: return null
                if (!take(':')) return null
                val value = readValue() ?: return null
                // See the class comment: no last-wins, no first-wins, no key twice.
                if (fields.put(key, value) != null) return null
                if (take(',')) continue
                return if (take('}')) JsonValue.Obj(fields) else null
            }
        }

        private fun readArray(): JsonValue? {
            if (!take('[')) return null
            val items = ArrayList<JsonValue>()
            if (take(']')) return JsonValue.Arr(items)
            while (true) {
                items.add(readValue() ?: return null)
                if (take(',')) continue
                return if (take(']')) JsonValue.Arr(items) else null
            }
        }

        @Suppress("CyclomaticComplexMethod")
        private fun readString(): String? {
            if (!take('"')) return null
            val out = StringBuilder()
            while (true) {
                val c = peek() ?: return null
                at++
                when {
                    c == '"' -> return out.toString()
                    c == '\\' -> out.append(readEscape() ?: return null)
                    // The serialiser escapes every one of these, so seeing one raw means the
                    // bytes did not come from it.
                    c < ' ' -> return null
                    else -> out.append(c)
                }
            }
        }

        private fun readEscape(): Char? {
            val c = peek() ?: return null
            at++
            return when (c) {
                '"' -> '"'
                '\\' -> '\\'
                'n' -> '\n'
                'r' -> '\r'
                't' -> '\t'
                'u' -> readUnicodeEscape()
                // `\/`, `\b` and `\f` are legal JSON that the serialiser never writes.
                else -> null
            }
        }

        private fun readUnicodeEscape(): Char? {
            if (at + HEX_LENGTH > text.length) return null
            var code = 0
            for (i in 0 until HEX_LENGTH) {
                val digit = hexValue(text[at + i]) ?: return null
                code = code * HEX_RADIX + digit
            }
            at += HEX_LENGTH
            return code.toChar()
        }

        private fun hexValue(c: Char): Int? = when (c) {
            in '0'..'9' -> c - '0'
            // Lower case only: the writer emits lower case, so upper case is a second
            // spelling of the same character.
            in 'a'..'f' -> c - 'a' + DECIMAL_RADIX
            else -> null
        }

        private fun readNumber(): JsonValue? {
            val start = at
            if (take('-')) {
                // Guard against a bare "-".
                if (peek() == null) return null
            }
            val digitsStart = at
            while (peek()?.isDigit() == true) at++
            val digits = text.substring(digitsStart, at)
            if (digits.isEmpty()) return null
            // "01" and "1" are the same value spelled two ways; the writer emits one.
            if (digits.length > 1 && digits[0] == '0') return null
            // No fractions and no exponents: coverage is per mille precisely so that no
            // number in this format is a float. Accepting one would accept a value the
            // canonical form cannot represent.
            if (peek() == '.' || peek() == 'e' || peek() == 'E') return null
            val raw = text.substring(start, at)
            if (raw == "-0") return null
            return raw.toLongOrNull()?.let { JsonValue.Num(it) }
        }
    }

    private const val HEX_LENGTH = 4
    private const val HEX_RADIX = 16
    private const val DECIMAL_RADIX = 10
}
