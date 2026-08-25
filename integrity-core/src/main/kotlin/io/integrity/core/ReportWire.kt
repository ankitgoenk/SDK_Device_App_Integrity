package io.integrity.core

/**
 * Canonical wire form of an [IntegrityReport].
 *
 * Canonical because the backend will eventually verify a signature over these bytes, and a
 * signature over a representation that can render two ways is a signature over nothing.
 * Two serialisations of the same report must be byte-identical on every device, every
 * architecture and every locale.
 *
 * Hand-rolled rather than delegating to a JSON library: hard rule 7 keeps third-party
 * runtime dependencies out of `integrity-core`, and a canonical form is precisely the thing
 * you want to be able to read in full rather than infer from a library's defaults.
 *
 * The rules, all of which exist because breaking one produces bytes that differ without the
 * report differing:
 *
 * 1. **Object keys are sorted lexicographically.** Map iteration order is not a contract.
 * 2. **No insignificant whitespace.**
 * 3. **Coverage is an integer per mille, never a float.** `Float.toString` is the single
 *    largest canonicalisation hazard here: it is locale-sensitive in some runtimes, and
 *    0.83f has no exact binary representation, so the decimal it prints is a property of
 *    the formatter rather than of the value. An integer 0..1000 has one spelling.
 * 4. **Signals are sorted** by id, then confidence, then their own canonical form. Detector
 *    registration order must not change the bytes.
 * 5. **Evidence keys are sorted**, for the same reason as 1.
 *
 * What is deliberately *not* here: `verdict` and `riskScore` at the top level. They live
 * under `clientAdvisory`, because a field named `verdict` beside the evidence invites a
 * reader to treat it as the answer. See ADR-0006.
 */
public object ReportWire {

    /** Bumped when the canonical form changes in a way that would alter existing bytes. */
    public const val WIRE_VERSION: Int = 1

    private const val PER_MILLE = 1000
    private val HEX_DIGITS = "0123456789abcdef".toCharArray()

    private const val BITS_PER_NIBBLE = 4
    private const val NIBBLES_PER_ESCAPE = 4
    private const val NIBBLE_MASK = 0xF

    /**
     * @param challenge the server-issued nonce this evaluation answers, echoed so the
     *   backend can bind report to request. Absent for an unchallenged evaluation, which
     *   the backend should treat as unbindable rather than as fresh.
     */
    public fun canonicalJson(report: IntegrityReport, challenge: String? = null): String {
        val advisory = obj(
            "categoryScores" to obj(
                report.categoryScores.entries
                    .map { it.key.name to num(it.value.toLong()) }
                    .sortedBy { it.first }
            ),
            "riskScore" to num(report.riskScore.toLong()),
            "verdict" to str(report.verdict.name)
        )

        return obj(
            "challenge" to (challenge?.let { str(it) } ?: "null"),
            "clientAdvisory" to advisory,
            // Per mille, not a float. See rule 3 above.
            "coveragePermille" to num(coveragePermille(report.coverage)),
            "depth" to str(report.depth.name),
            "generatedAtMillis" to num(report.generatedAtMillis),
            "reportId" to str(report.reportId),
            "sdkVersion" to str(report.sdkVersion),
            "signals" to array(report.signals.map(::signal).sorted()),
            "wireVersion" to num(WIRE_VERSION.toLong())
        )
    }

    /**
     * Rounds half-up into 0..1000.
     *
     * Clamped rather than trusted: coverage is a fraction by contract, and a value outside
     * it would be a bug elsewhere that should not become unparseable bytes here.
     */
    internal fun coveragePermille(coverage: Float): Long {
        if (coverage.isNaN()) return 0L
        val scaled = Math.round(coverage.toDouble() * PER_MILLE)
        return scaled.coerceIn(0L, PER_MILLE.toLong())
    }

    private fun signal(signal: Signal): String = obj(
        "category" to str(signal.category.name),
        "confidence" to str(signal.confidence.name),
        "evidence" to obj(signal.evidence.entries.map { it.key to str(it.value) }.sortedBy { it.first }),
        "id" to str(signal.id.value)
    )

    private fun obj(vararg entries: Pair<String, String>): String = obj(entries.toList())

    private fun obj(entries: List<Pair<String, String>>): String =
        entries.sortedBy { it.first }.joinToString(",", "{", "}") { "${str(it.first)}:${it.second}" }

    private fun array(values: List<String>): String = values.joinToString(",", "[", "]")

    private fun num(value: Long): String = value.toString()

    /**
     * Hand-rolled hex, because `String.format` uses the default locale.
     *
     * Caught by detekt, and it is the exact hazard this file's own header warns about two
     * functions higher up: a canonical form must not contain a single locale-dependent
     * rendering. Writing the nibbles directly removes the question rather than answering it
     * with `Locale.ROOT`.
     */
    private fun appendUnicodeEscape(out: StringBuilder, code: Int) {
        out.append("\\u")
        // Most significant nibble first, so 0x1f renders as 001f rather than f100.
        for (position in NIBBLES_PER_ESCAPE - 1 downTo 0) {
            out.append(HEX_DIGITS[(code shr (position * BITS_PER_NIBBLE)) and NIBBLE_MASK])
        }
    }

    /** Minimal, deterministic JSON string escaping. */
    private fun str(value: String): String {
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
}
