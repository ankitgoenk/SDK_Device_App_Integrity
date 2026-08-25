package io.integrity.nativecore

import io.integrity.core.Category
import io.integrity.core.Confidence
import io.integrity.core.Depth
import io.integrity.core.DetectionContext
import io.integrity.core.Detector
import io.integrity.core.Signal
import io.integrity.core.SignalId

/**
 * `HOOK_SELF_TEXT_MISMATCH` — this SDK's executing code differs from the file it was
 * loaded from.
 *
 * Full design, written and reviewed before this existed:
 * `docs/detectors/HOOK_SELF_TEXT_MISMATCH.md`.
 *
 * **Evidence.** Byte counts and an offset within our own mapping. No paths, no package
 * names, nothing about the user or the device.
 *
 * **Expected result.** `POSSIBLE` and never higher, on any device. The measurement is
 * exact — bytes either match or they do not — but what a mismatch *means* is not, and the
 * confidence describes the inference rather than the arithmetic.
 *
 * **Known bypass.** Six, four of them cheap, all written down before implementation.
 * Hooking `pread` or `open` feeds this check the original bytes. Restore-on-read defeats
 * it. Hooking a different module avoids it. And GOT/PLT redirection or an ART entry-point
 * swap changes no executable byte at all, so this sees nothing — that is the largest blind
 * spot and it is not closable from here.
 *
 * **False positives.** The one that would have stopped this shipping is text relocations
 * making a clean process look modified. Measured before the detector was written: 12,288
 * bytes compared, zero differing, on both a release-keys and a userdebug image (PR #12).
 * Legitimate runtime patching by a host or an OEM remains possible in the field, which is
 * the other reason the confidence is capped.
 *
 * **What this does not prove.** Not that the process is hooked — only that in-memory code
 * differs from its file. Not that the process is clean when silent: bypasses 1–4 leave it
 * silent. Not anything about other libraries. Not anything about a `.so` that was already
 * tampered with on disk, where memory and file agree because both are the attacker's.
 */
internal class SelfTextDetector(private val api: NativeApi = NativeBridge) : Detector {

    override val id: String = "hooking.self-text"
    override val category: Category = Category.HOOKING

    // FULL only. This reads the library off disk and compares it to memory; it should not
    // masquerade as a check cheap enough for the startup path.
    override val minDepth: Depth = Depth.FULL

    override suspend fun detect(context: DetectionContext): List<Signal> {
        val values = runCatching { api.measureSelfText() }.getOrNull()
            ?: return listOf(inconclusive("call_failed"))
        if (values.size < EXPECTED_VALUES) {
            return listOf(inconclusive("malformed_result"))
        }

        val status = values[NativeCore.MEASURE_STATUS].toInt()
        if (status != NativeCore.STATUS_OK) {
            return listOf(inconclusive(reasonOf(values[NativeCore.MEASURE_REASON].toInt())))
        }

        val compared = values[NativeCore.MEASURE_BYTES_COMPARED]
        val differing = values[NativeCore.MEASURE_BYTES_DIFFERING]

        // Belt and braces with the native side, which already refuses to report success
        // having compared nothing. A zero here would otherwise be indistinguishable from a
        // clean result, and that confusion is the whole subject of this detector's design.
        if (compared <= 0L) {
            return listOf(inconclusive("nothing_compared"))
        }
        if (differing == 0L) {
            return emptyList()
        }

        return listOf(
            Signal(
                id = SignalId.HOOK_SELF_TEXT_MISMATCH,
                category = Category.HOOKING,
                confidence = Confidence.POSSIBLE,
                evidence = mapOf(
                    "region" to "self_text",
                    "bytesCompared" to compared.toString(),
                    "bytesDiffering" to differing.toString(),
                    "firstDifferenceAt" to values[NativeCore.MEASURE_FIRST_DIFFERENCE].toString()
                )
            )
        )
    }

    private fun inconclusive(reason: String) = Signal(
        id = SignalId.HOOK_SELF_TEXT_MISMATCH,
        category = Category.HOOKING,
        confidence = Confidence.INCONCLUSIVE,
        evidence = mapOf("reason" to reason)
    )

    private fun reasonOf(code: Int): String = when (code) {
        NativeCore.REASON_MAPS_UNREADABLE -> "maps_unreadable"
        NativeCore.REASON_SELF_MAPPING_NOT_FOUND -> "self_mapping_not_found"
        NativeCore.REASON_LIBRARY_FILE_UNREADABLE -> "library_file_unreadable"
        NativeCore.REASON_MEMORY_UNREADABLE -> "memory_unreadable"
        NativeCore.REASON_NOTHING_COMPARED -> "nothing_compared"
        else -> "unavailable"
    }

    private companion object {
        const val EXPECTED_VALUES = 6
    }
}
