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
    public val category: Category,
    public val confidence: Confidence,
    public val evidence: Map<String, String> = emptyMap(),
    public val detectorVersion: Int = 1,
    public val detectedAtMillis: Long = System.currentTimeMillis()
) {
    override fun toString(): String = "Signal(${id.value}, $confidence)"

    override fun equals(other: Any?): Boolean = other is Signal && other.id == id && other.confidence == confidence

    override fun hashCode(): Int = 31 * id.hashCode() + confidence.hashCode()
}
