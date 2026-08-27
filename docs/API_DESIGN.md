# Public API Design

Target surface for `integrity-core`. Kotlin-first, Java-friendly, binary-compatibility
checked in CI. Everything below is a design target for Phase 1, not shipped code.

## Entry point

```kotlin
object IntegrityGuard {

    /** Idempotent. Safe to call from Application.onCreate; does no blocking work. */
    @JvmStatic
    fun initialize(context: Context, config: IntegrityConfig)

    /** Last cached report, or an UNKNOWN report if none yet. Never blocks. */
    @JvmStatic
    fun currentReport(): IntegrityReport

    /** Runs (or reuses a cached) evaluation at the requested depth. */
    suspend fun evaluate(depth: Depth = Depth.STANDARD, force: Boolean = false): IntegrityReport

    /** Java/callback variant. Returns a handle that can be cancelled. */
    @JvmStatic
    fun evaluateAsync(depth: Depth, callback: ResultCallback): Cancellable

    /** Cold flow: emits on every completed evaluation (manual or scheduled). */
    fun reports(): Flow<IntegrityReport>

    /** Point-in-time check for a sensitive UI moment (overlay/capture). Cheap. */
    @JvmStatic
    fun checkInteractionSafety(activity: Activity): InteractionSafety

    @JvmStatic
    fun shutdown()
}
```

### Depth

```kotlin
enum class Depth { QUICK, STANDARD, FULL }
```

| Depth | Budget | Contains | Call from |
| --- | --- | --- | --- |
| `QUICK` | ≤ 20 ms | Cached results + O(1) property/flag checks | Anywhere, including per-screen |
| `STANDARD` | ≤ 150 ms | + filesystem probes, package queries, JVM hook probes | App start, foreground resume |
| `FULL` | ≤ 1 s | + native memory/maps scan, port probes, digest verification, attestation | App start (background), before high-value actions |

## Configuration

```kotlin
class IntegrityConfig private constructor(...) {
    class Builder {
        /** Required for APP_SIGNATURE_MISMATCH. Accepts multiple for key rotation. */
        fun expectedSigningCertSha256(vararg sha256: String): Builder
        fun expectedPackageName(name: String): Builder

        /** Explicit detector registration — no reflection, tree-shakeable. */
        fun detectors(detectors: List<Detector>): Builder
        fun addDetector(detector: Detector): Builder

        fun policy(policy: Policy): Builder
        /** Apply host-fetched policy overrides (JSON). */
        fun policyOverrides(json: String): Builder

        fun reportSink(sink: ReportSink): Builder
        fun signing(signer: ReportSigner): Builder      // see SERVER_VERIFICATION.md

        /** Packages the host considers legitimate (e.g. its own MDM, a11y allowlist). */
        fun allowlistPackages(vararg pkg: String): Builder

        fun cacheTtl(depth: Depth, ttl: Duration): Builder
        fun detectorBudget(budget: Duration): Builder   // default 250 ms per detector
        fun logger(logger: IntegrityLogger): Builder    // no logging by default in release

        fun build(): IntegrityConfig
    }
}
```

## Data model

```kotlin
@JvmInline value class SignalId(val value: String)   // stable strings, e.g. "ROOT_MAGISK_PATHS"

enum class Category { ROOT, HOOKING, APP_TAMPER, ENVIRONMENT, EMULATION, ATTESTATION, META }

enum class Confidence { CONFIRMED, LIKELY, POSSIBLE, INCONCLUSIVE }

class Signal(
    val id: SignalId,
    val category: Category,
    val confidence: Confidence,
    /** Bounded, non-PII detail: matched-artefact class, counts, hashed package ids. */
    val evidence: Map<String, String>,
    val detectorVersion: Int,
    val detectedAtMillis: Long,
)

enum class Verdict { NO_EVIDENCE_OF_COMPROMISE, LOW_RISK, SUSPICIOUS, COMPROMISED, UNKNOWN }
// No rung means "trusted": ADR-0009. The bottom one is an absence, not a pass.

class IntegrityReport(
    val verdict: Verdict,
    val riskScore: Int,                       // 0..100
    val categoryScores: Map<Category, Int>,
    val signals: List<Signal>,
    val coverage: Float,                      // 0f..1f — see RISK_SCORING.md
    val depth: Depth,
    val generatedAtMillis: Long,
    val sdkVersion: String,
    val reportId: String,                     // uuid, for correlating with backend logs
) {
    /** Canonical, versioned JSON for transport. */
    fun toCanonicalJson(): String
    /** Canonical JSON + signature + nonce binding, when a ReportSigner is configured. */
    fun toSignedPayload(nonce: String): SignedPayload
}

class InteractionSafety(
    val obscured: Boolean,
    val screenCaptureActive: Boolean,
    val suspiciousAccessibility: Boolean,
    val signals: List<Signal>,
)
```

### Evidence discipline

`evidence` is deliberately a `Map<String, String>` with a documented, bounded key set per
signal — never free-form dumps. Rules:

- No absolute paths outside a fixed enum of known artefact classes.
- No raw package names for third-party apps in reports that leave the device; use
  `sha256(packageName)` truncated to 16 hex chars, plus a category label
  (`patcher`, `memory_editor`, …). The host may opt in to clear names for internal builds.
- No IMEI, ANDROID_ID, MAC, account, or location data. Ever.
- Total serialised evidence per report capped (default 8 KB).

## Detector SPI

```kotlin
interface Detector {
    val id: String
    val category: Category
    val minDepth: Depth              // skipped when evaluate() runs shallower
    val budget: Duration get() = 250.milliseconds

    suspend fun detect(context: DetectionContext): List<Signal>
}

interface DetectionContext {
    val appContext: Context
    val config: IntegrityConfig
    val native: NativeBridge?        // null when the native lib is unavailable
    fun cacheGet(key: String): String?
    fun cachePut(key: String, value: String, ttl: Duration)
}
```

A detector that cannot reach a conclusion **must** return a signal with
`Confidence.INCONCLUSIVE` rather than an empty list, so coverage stays honest.

## Sinks

```kotlin
fun interface ReportSink {
    /** Called off the main thread. Must not throw; must not block long. */
    fun onReport(report: IntegrityReport)
}
```

Provided implementations: `LogcatSink` (debug), `InMemorySink` (tests), `CompositeSink`.
There is deliberately **no** HTTP sink — the host owns the network stack, its pinning and
its consent model.

## Error handling

- The SDK throws only from `initialize()`, and only for programmer error (null context,
  malformed pin). Everything else degrades to signals.
- Calls before `initialize()` return an `UNKNOWN` report with `META_CONFIG_INVALID`.
- Native load failure produces `META_NATIVE_UNAVAILABLE`; the SDK stays functional at the
  JVM layer.

## API stability policy

- `SignalId` strings and `Verdict`/`Category` enum names are contract; additions only.
- New enum constants may appear in minor releases — hosts must handle unknown values (an
  `else` branch), which is documented in [INTEGRATION.md](INTEGRATION.md).
- `binary-compatibility-validator` API dumps are committed; a change to `api/*.api` requires
  explicit review.
