package io.integrity.detector.app

import io.integrity.core.Category
import io.integrity.core.Confidence
import io.integrity.core.Depth
import io.integrity.core.DetectionContext
import io.integrity.core.Detector
import io.integrity.core.Signal
import io.integrity.core.SignalId

/**
 * `APP_DEX_DIGEST_MISMATCH` — the running APK's dex does not match the build that produced it.
 *
 * **Evidence.** An aggregate digest of every `classes*.dex` entry, and how many there were.
 * Nothing about the user or the device; these are digests of our own code.
 *
 * **Expected result.** `CONFIRMED` when a baseline is configured and the measurement differs —
 * this id is in `RiskScorer.DECISIVE_SIGNALS`, so a confirmed instance escalates to
 * `COMPROMISED` on its own — **once it carries a weight above `INFORMATIONAL`**, which
 * `AppDetectors.proposedWeights` is the shipped route to. `RiskScorer.escalate` never sees an
 * unpromoted signal, so until a host composes that helper this fires and scores zero.
 * `INCONCLUSIVE` in every case where the comparison could not be
 * made, with the reason attached, because a check that could not run is not a clean result.
 *
 * ### The baseline comes from outside, and that is the whole design
 *
 * `integrity-baseline-plugin` computes the expected aggregate at build time. It cannot be
 * embedded in the APK it describes — a digest of an artifact cannot live inside that artifact —
 * so the host supplies it through [io.integrity.core.IntegrityConfig.Builder.expectedDexDigest],
 * and the same measurement travels in the report for a backend holding the baseline
 * independently to check. A client comparing against a baseline it shipped alongside the code
 * an attacker rewrote proves little on its own; the report is where the comparison has teeth.
 *
 * **Known bypass.** Everything that defeats a measurement taken by the code being measured.
 * A hooked `ZipFile`/`open` returns the original bytes. A patched detector returns a matching
 * digest. On a rooted device this is a speed bump, and the honest reading of a match is "the
 * client says it matches", which is why the measurement is reported rather than merely acted on.
 *
 * **False positives.** The dangerous one is a **split install**: the baseline covers the base
 * APK, so on Play Feature Delivery or an app bundle with configuration splits we would be
 * comparing part of an app against a whole one. The detector declines rather than accuses when
 * splits are present — an `APP_*` false positive is an accusation that the host's own app is
 * not its app, and this signal escalates decisively.
 */
internal class DexDigestDetector(private val probe: ApkDexProbe? = null) : Detector {

    override val id: String = "app.dex-digest"
    override val category: Category = Category.APP_TAMPER

    // FULL only: this opens and digests a multi-megabyte archive.
    override val minDepth: Depth = Depth.FULL

    @Suppress("ReturnCount")
    override suspend fun detect(context: DetectionContext): List<Signal> {
        val apk = probe ?: RealApkDexProbe(context.appContext)

        val splits = apk.splitCount()
        if (splits > 0) {
            // Declining, not accusing. See the false-positive note above.
            return listOf(inconclusive("split_apks_present", mapOf("splits" to splits.toString())))
        }

        val path = apk.baseApkPath()
            ?: return listOf(inconclusive("apk_path_unavailable"))

        val measured = ApkDexMeasurement.of(path)
            ?: return listOf(inconclusive("apk_unreadable"))

        val evidence = mapOf(
            "dexDigest" to measured.digest,
            "dexCount" to measured.entryCount.toString()
        )

        val expected = context.config.expectedDexDigest
            // No baseline is the ordinary state of an integration that has not adopted the
            // plugin. The measurement still travels, so a backend that holds the baseline can
            // do the comparison this client cannot.
            ?: return listOf(inconclusive("no_baseline_configured", evidence))

        return if (expected.equals(measured.digest, ignoreCase = true)) {
            emptyList()
        } else {
            listOf(
                Signal(
                    id = SignalId.APP_DEX_DIGEST_MISMATCH,
                    category = Category.APP_TAMPER,
                    confidence = Confidence.CONFIRMED,
                    evidence = evidence
                )
            )
        }
    }

    private fun inconclusive(reason: String, extra: Map<String, String> = emptyMap()) = Signal(
        id = SignalId.APP_DEX_DIGEST_MISMATCH,
        category = Category.APP_TAMPER,
        confidence = Confidence.INCONCLUSIVE,
        evidence = mapOf("reason" to reason) + extra
    )
}
