package io.integrity.detector.root

import io.integrity.core.Category
import io.integrity.core.Confidence
import io.integrity.core.Depth
import io.integrity.core.DetectionContext
import io.integrity.core.Detector
import io.integrity.core.Signal
import io.integrity.core.SignalId

/**
 * ROOT_MANAGER_PACKAGE — a known root-manager application is installed.
 *
 * **Evidence.** `packages`, a comma-separated list of 16-hex-character SHA-256 prefixes,
 * and `count`. Clear package names never leave the device (P4): the backend can match the
 * digests against its own list without the SDK shipping an inventory of installed apps.
 *
 * **Expected result.** A visible match is LIKELY rather than CONFIRMED — the manager being
 * installed says root is *available*, not that this process is running rooted, and someone
 * may have flashed it away and left the app behind.
 *
 * When nothing matches, the answer depends on whether absence can be believed. From API 30,
 * package visibility filtering makes "not installed" and "not visible to you" identical, so
 * the detector reports INCONCLUSIVE instead of a clean result. That is deliberate, and it
 * costs coverage on every modern device: it is the honest price of not declaring
 * QUERY_ALL_PACKAGES (ADR-0004).
 *
 * **Known bypass.** Very easy. Magisk supports repackaging its manager under a random
 * package name, which defeats a fixed list outright; uninstalling the manager while keeping
 * root defeats it too. Treat a hit as useful evidence and a miss as no evidence.
 *
 * **False positives.** Low for the detection itself, but the *inference* is where the risk
 * sits: a user may have the manager installed on a device that is no longer rooted. That is
 * why the weight is conservative and the confidence is LIKELY.
 */
internal class RootManagerPackageDetector(
    /** Overridden in tests; production builds the probe from the detection context. */
    private val probe: PackageProbe? = null
) : Detector {

    override val id: String = "root.manager-package"
    override val category: Category = Category.ROOT
    override val minDepth: Depth = Depth.STANDARD

    override suspend fun detect(context: DetectionContext): List<Signal> {
        val packages = probe ?: RealPackageProbe(context.appContext)
        val allowlisted = context.config.allowlistedPackages
        val found = MANAGER_PACKAGES
            .filterNot { it in allowlisted }
            .filter(packages::isInstalled)

        if (found.isNotEmpty()) {
            return listOf(
                Signal(
                    id = SignalId.ROOT_MANAGER_PACKAGE,
                    category = Category.ROOT,
                    confidence = Confidence.LIKELY,
                    evidence = mapOf(
                        "packages" to found.joinToString(",", transform = ::hashPackageName),
                        "count" to found.size.toString()
                    )
                )
            )
        }

        if (packages.absenceIsConclusive) return emptyList()

        return listOf(
            Signal(
                id = SignalId.ROOT_MANAGER_PACKAGE,
                category = Category.ROOT,
                confidence = Confidence.INCONCLUSIVE,
                evidence = mapOf("reason" to "package_visibility_filtered")
            )
        )
    }

    private companion object {
        // Mirrors the <queries> fragment shipped by integrity-detector-environment; a
        // package absent from that list is invisible to us regardless of what we probe.
        val MANAGER_PACKAGES = listOf(
            "com.topjohnwu.magisk",
            "me.weishu.kernelsu",
            "eu.chainfire.supersu",
            "com.koushikdutta.superuser",
            "com.noshufou.android.su"
        )
    }
}
