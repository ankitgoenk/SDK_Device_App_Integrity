package io.integrity.core

/**
 * One observation from one detector.
 *
 * [evidence] is deliberately a small, bounded map with a documented key set per signal.
 * It must never contain personal or device-identifying data: no IMEI, ANDROID_ID, MAC,
 * accounts or location, and third-party package names only as truncated hashes.
 * See docs/PRIVACY_AND_COMPLIANCE.md, rules P1-P8.
 */
public class Signal(
    public val id: SignalId,
    /**
     * The family this signal belongs to. **Defaults to the one [id] implies, and should be
     * left to.**
     *
     * A signal's category is a fact about its id — `HOOK_UNEXPECTED_MODULE` is always
     * `HOOKING` — and `docs/DETECTION_CATALOG.md` is organised by exactly that. It was a free
     * parameter, which mattered once the backend started deriving it: `SubmittedReports`
     * computes the category from the id rather than reading it off the wire, so a client that
     * passed something else would make the two ends score one report differently. That is the
     * [DexAggregate] failure mode — two implementations of one rule — reached by a different
     * route.
     *
     * Passing it explicitly is still allowed, because an integrator feeding their own
     * attestation verdict in may use an id from no family this build knows. Where the id *is*
     * known, `tools/check-signal-catalog.py` fails the build if an explicit value contradicts
     * it.
     */
    public val category: Category = SignalCategories.of(id) ?: Category.META,
    public val confidence: Confidence,
    public val evidence: Map<String, String> = emptyMap(),
    public val detectorVersion: Int = 1,
    public val detectedAtMillis: Long = System.currentTimeMillis()
) {
    override fun toString(): String = "Signal(${id.value}, $confidence)"

    override fun equals(other: Any?): Boolean = other is Signal && other.id == id && other.confidence == confidence

    override fun hashCode(): Int = 31 * id.hashCode() + confidence.hashCode()
}
