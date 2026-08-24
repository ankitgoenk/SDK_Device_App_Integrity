package io.integrity.detector.app

import io.integrity.core.Category
import io.integrity.core.Confidence
import io.integrity.core.Depth
import io.integrity.core.DetectionContext
import io.integrity.core.Detector
import io.integrity.core.Signal
import io.integrity.core.SignalId

/**
 * APP_SIGNATURE_MISMATCH — the running APK is not signed by a pinned certificate.
 *
 * **Evidence.** `signerCount`, `observedSigner` (first 16 hex of the SHA-256 of the
 * certificate actually signing us), `api`, and on the inconclusive paths a `reason`. A
 * certificate digest describes the build, not the user, so it is safe to report and is
 * what a backend needs to tell "signed by our old key" from "signed by someone else".
 *
 * **Expected result.** No signal when a pin matches the current signer, and no signal when
 * a pin matches an ancestor in the signing lineage — that is legitimate key rotation, not
 * tampering. On a genuine mismatch: CONFIRMED from API 28, where `signingInfo` and the
 * lineage API are available; LIKELY on API 24-27, which only exposes `GET_SIGNATURES` with
 * no lineage and a weaker history. Missing pins or unreadable signing information are
 * INCONCLUSIVE, never clean.
 *
 * **Known bypass.** Straightforward, and this is the important caveat: everything here
 * comes from `PackageManager`, which is precisely what an attacker who has repackaged the
 * app controls. Hooking `getPackageInfo` or `hasSigningCertificate` to return the expected
 * digest is a published one-liner. This signal raises the cost of a naive repackage and
 * produces evidence; it does not stop anyone competent. Enforcement comes from the
 * build-time dex/APK digests verified natively (phase 4) and from Play Integrity's
 * `appRecognitionVerdict` checked server-side (phase 7), neither of which the client can
 * talk its way out of.
 *
 * **False positives.** The dangerous one is not a device configuration but a *release
 * process* mistake: with Google Play App Signing the key you upload with is not the key
 * Google distributes with, so pinning the upload key makes this detector fire for every
 * legitimate user of a Play-distributed build. Pin the app signing key from the Play
 * Console. Rotation is handled via the lineage check; multi-signer APKs are reported but
 * not treated as a mismatch on their own.
 */
internal class SignatureDetector(
    /** Overridden in tests; production builds the probe from the detection context. */
    private val probe: SigningInfoProbe? = null
) : Detector {

    override val id: String = "app.signature"
    override val category: Category = Category.APP_TAMPER
    override val minDepth: Depth = Depth.STANDARD

    override suspend fun detect(context: DetectionContext): List<Signal> {
        val pins = context.config.expectedSigningCertSha256
        if (pins.isEmpty()) return listOf(inconclusive("no_pin_configured", apiOf(context)))

        val signing = probe ?: RealSigningInfoProbe(context.appContext)
        val signers = signing.currentSigners()
        if (signers.isNullOrEmpty()) {
            return listOf(inconclusive("signing_info_unavailable", signing.apiLevel))
        }

        return if (isTrusted(pins, signers, signing)) emptyList() else listOf(mismatch(signers, signing))
    }

    private fun isTrusted(pins: Set<String>, signers: List<String>, signing: SigningInfoProbe): Boolean {
        if (pins.any { it in signers }) return true
        // Legitimate rotation: the pin is an ancestor of the certificate signing us now.
        return signing.apiLevel >= API_SIGNING_INFO && pins.any(signing::matchesLineage)
    }

    private fun mismatch(signers: List<String>, signing: SigningInfoProbe): Signal = Signal(
        id = SignalId.APP_SIGNATURE_MISMATCH,
        category = Category.APP_TAMPER,
        confidence = if (signing.apiLevel >= API_SIGNING_INFO) {
            Confidence.CONFIRMED
        } else {
            Confidence.LIKELY
        },
        evidence = mapOf(
            "signerCount" to signers.size.toString(),
            "multipleSigners" to signing.hasMultipleSigners().toString(),
            "observedSigner" to signers.first().take(SIGNER_PREFIX),
            "api" to signing.apiLevel.toString()
        )
    )

    private fun apiOf(context: DetectionContext): Int =
        probe?.apiLevel ?: RealSigningInfoProbe(context.appContext).apiLevel

    private fun inconclusive(reason: String, apiLevel: Int) = Signal(
        id = SignalId.APP_SIGNATURE_MISMATCH,
        category = Category.APP_TAMPER,
        confidence = Confidence.INCONCLUSIVE,
        evidence = mapOf("reason" to reason, "api" to apiLevel.toString())
    )

    private companion object {
        /** API 28: signingInfo, the lineage, and hasSigningCertificate all arrive here. */
        const val API_SIGNING_INFO = 28
        const val SIGNER_PREFIX = 16
    }
}
