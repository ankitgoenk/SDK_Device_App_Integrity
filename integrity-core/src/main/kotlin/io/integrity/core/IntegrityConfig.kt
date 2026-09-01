package io.integrity.core

import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

/** Immutable SDK configuration. Build with [Builder]; see docs/INTEGRATION.md. */
public class IntegrityConfig private constructor(
    public val expectedPackageName: String?,
    public val expectedSigningCertSha256: Set<String>,
    /**
     * Aggregate `classes*.dex` digest from `integrity-baseline-plugin`, if the host bakes one in.
     *
     * Null is the ordinary state: the digest of an artifact cannot live inside that artifact, so
     * supplying it is a deliberate act by the host. Absent it, the SDK still measures and reports,
     * and a backend holding the baseline performs the comparison instead.
     */
    public val expectedDexDigest: String?,
    public val detectors: List<Detector>,
    public val sink: ReportSink?,
    public val allowlistedPackages: Set<String>,
    public val detectorBudget: Duration,
    public val policy: Policy,
    public val cacheTtls: Map<Depth, Duration>
) {
    public class Builder {
        private var expectedPackageName: String? = null
        private var expectedDexDigest: String? = null
        private val signingPins = mutableSetOf<String>()
        private val detectors = mutableListOf<Detector>()
        private var sink: ReportSink? = null
        private val allowlist = mutableSetOf<String>()
        private var detectorBudget: Duration = Detector.DEFAULT_BUDGET
        private var policy: Policy = Policy.balanced()
        private val cacheTtls: MutableMap<Depth, Duration> = DEFAULT_CACHE_TTLS.toMutableMap()

        public fun expectedPackageName(name: String): Builder = apply {
            expectedPackageName = name
        }

        /** The aggregate dex digest emitted by `integrity-baseline-plugin` for this build. */
        public fun expectedDexDigest(digest: String): Builder = apply {
            expectedDexDigest = digest.trim()
        }

        /** Accepts several pins so signing-key rotation does not false-positive. */
        public fun expectedSigningCertSha256(vararg sha256: String): Builder = apply {
            signingPins += sha256.map { it.uppercase().replace(":", "") }
        }

        /** Explicit registration — no reflection, so unused detectors are strippable. */
        public fun detectors(detectors: List<Detector>): Builder = apply {
            this.detectors += detectors
        }

        public fun addDetector(detector: Detector): Builder = apply {
            detectors += detector
        }

        public fun reportSink(sink: ReportSink): Builder = apply {
            this.sink = sink
        }

        /** Packages the host considers legitimate, e.g. its MDM or an a11y allowlist. */
        public fun allowlistPackages(vararg packageName: String): Builder = apply {
            allowlist += packageName
        }

        public fun detectorBudget(budget: Duration): Builder = apply {
            detectorBudget = budget
        }

        /** Weights, thresholds and per-signal kill switches. See docs/RISK_SCORING.md. */
        public fun policy(policy: Policy): Builder = apply {
            this.policy = policy
        }

        public fun cacheTtl(depth: Depth, ttl: Duration): Builder = apply {
            cacheTtls[depth] = ttl
        }

        public fun build(): IntegrityConfig = IntegrityConfig(
            expectedPackageName = expectedPackageName,
            expectedSigningCertSha256 = signingPins.toSet(),
            expectedDexDigest = expectedDexDigest,
            detectors = detectors.toList(),
            sink = sink,
            allowlistedPackages = allowlist.toSet(),
            detectorBudget = detectorBudget,
            policy = policy,
            cacheTtls = cacheTtls.toMap()
        )
    }

    public companion object {
        public val MIN_BUDGET: Duration = 10.milliseconds

        internal val DEFAULT_CACHE_TTLS: Map<Depth, Duration> = mapOf(
            Depth.QUICK to 30.seconds,
            Depth.STANDARD to 60.seconds,
            Depth.FULL to 5.minutes
        )
    }
}
