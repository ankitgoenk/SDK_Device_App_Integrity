# Integration Guide (host app)

> Target-state guide. Nothing here is publishable until Phase 11.

## 1. Gradle

```kotlin
dependencies {
    implementation("io.integrity.sdk:integrity-core:<version>")

    // Pick the detector families you need — each is optional
    implementation("io.integrity.sdk:integrity-detector-root:<version>")
    implementation("io.integrity.sdk:integrity-detector-hooking:<version>")
    implementation("io.integrity.sdk:integrity-detector-app:<version>")
    implementation("io.integrity.sdk:integrity-detector-environment:<version>")
    implementation("io.integrity.sdk:integrity-detector-emulator:<version>")
}

plugins {
    id("io.integrity.sdk.baseline") version "<version>"   // bakes dex/lib digests + pins
}

integrityBaseline {
    // Read from your signing config / Play App Signing console — never hardcode in source
    expectedSigningCertSha256.set(providers.gradleProperty("integrity.signingCertSha256"))
    verifyDexDigests.set(true)
    obfuscateStrings.set(true)
}
```

The baseline plugin runs after packaging, computes digests of the produced artifact, and
writes them into the native string vault. This is why digests are never hand-maintained and
never wrong after an R8 change.

## 2. Initialisation

```kotlin
class App : Application() {
    override fun onCreate() {
        super.onCreate()

        IntegrityGuard.initialize(
            this,
            IntegrityConfig.Builder()
                .expectedPackageName(BuildConfig.APPLICATION_ID)
                .expectedSigningCertSha256(BuildConfig.SIGNING_CERT_SHA256)
                .detectors(
                    RootDetectors.all() +
                    HookDetectors.all() +
                    AppDetectors.all() +
                    EnvironmentDetectors.all() +
                    EmulatorDetectors.all()
                )
                .policy(Policy.balanced())
                .reportSink { report -> integrityRepository.enqueue(report) }
                .build()
        )

        // Kick off a full sweep off the critical path
        appScope.launch { IntegrityGuard.evaluate(Depth.FULL) }
    }
}
```

**Do not** call `evaluate()` synchronously on the main thread, and do not gate your splash
screen on it. Use `currentReport()` (cached, non-blocking) for UI decisions and let the full
sweep land asynchronously.

## 3. Manifest

### Package visibility (Android 11+)

On `targetSdk` 30+, `PackageManager` results are filtered. To probe for hostile apps you must
declare each package you want to see. **Do not request `QUERY_ALL_PACKAGES`** — Google Play
restricts it to a narrow set of use cases and integrity scanning is not reliably accepted;
requesting it risks removal.

```xml
<manifest>
    <queries>
        <!-- Root managers -->
        <package android:name="com.topjohnwu.magisk" />
        <package android:name="me.weishu.kernelsu" />
        <!-- Patchers / memory editors / MITM tools: see the curated list shipped with
             integrity-detector-environment as queries_integrity.xml -->
    </queries>
</manifest>
```

The environment detector module ships a manifest fragment with the curated list, so the
merged manifest picks it up automatically. Suppress it if you prefer to curate your own:

```xml
<queries tools:node="remove" />
```

**Consequence of not declaring a package:** the probe returns "not found", which is
indistinguishable from "not installed". The SDK therefore reports
`META_VISIBILITY_RESTRICTED` and marks affected signals `INCONCLUSIVE` — it never claims the
device is clean on the strength of a filtered query.

### Permissions

The SDK requires **no** permissions. Optional capabilities:

| Capability | Permission | Needed for |
| --- | --- | --- |
| Report upload | `INTERNET` | Host's own network layer, not the SDK |
| Nothing else | — | All detection is permissionless |

If your app already holds `QUERY_ALL_PACKAGES` for an approved reason, the SDK will use the
broader visibility automatically — but it must not be added for the SDK's sake.

## 4. R8 / ProGuard

The AAR ships consumer rules; no host configuration is normally required. If you use
aggressive optimisation, keep:

```proguard
# Native bridge is registered dynamically — do not rename the loader class
-keep class io.integrity.native.NativeBridge { *; }
# Signal ids are compared as strings and appear in reports
-keepclassmembers enum io.integrity.core.** { *; }
```

Do **not** add `-keep class io.integrity.** { *; }` — that defeats the SDK's own obfuscation.

## 5. Reacting to reports

```kotlin
when (val r = IntegrityGuard.currentReport()) {
    else -> when (r.verdict) {
        Verdict.TRUSTED, Verdict.LOW_RISK -> Unit
        Verdict.SUSPICIOUS -> analytics.flag(r.reportId)          // observe, don't block
        Verdict.COMPROMISED -> featureFlags.disableSensitive()     // degrade quietly
        Verdict.UNKNOWN -> scheduleRetry()
        // handle unknown future enum values defensively
    }
}
```

### Sensitive-moment checks

```kotlin
binding.pinEntry.filterTouchesWhenObscured = true

val safety = IntegrityGuard.checkInteractionSafety(this)
if (safety.obscured || safety.screenCaptureActive) {
    // Do not accept the PIN entry this time; explain generically
}
```

### Getting the decision server-side

```kotlin
val nonce = api.fetchNonce()                          // server-issued, single use
val payload = IntegrityGuard.evaluate(Depth.FULL).toSignedPayload(nonce)
api.submitIntegrity(payload)                          // backend decides
```

See [SERVER_VERIFICATION.md](SERVER_VERIFICATION.md). **Any decision that matters to your
business must be made on the response from your backend, not on the client verdict.**

## 6. Rollout plan for an integrator

1. **Release N:** integrate with `Policy.observability()`. Report only. Collect distributions.
2. **Release N+1:** tune weights and allowlists from the observed distribution; enable
   server-side flagging (still no user-visible effect).
3. **Release N+2:** enable step-up authentication for `SUSPICIOUS` on high-value actions.
4. **Release N+3:** enable degradation for `COMPROMISED`, with a support runbook and a
   remote kill switch for every enforced signal.

Never ship straight to enforcement. The first production release always tells you something
about your user base that the test matrix did not.

## 7. Common pitfalls

| Pitfall | Fix |
| --- | --- |
| Gating app start on `evaluate(FULL)` | Use `currentReport()`; run `FULL` in the background |
| Treating `UNKNOWN` as clean | Treat as `SUSPICIOUS` for high-value actions |
| Blocking users with accessibility services enabled | Never enforce on `ENV_ACCESSIBILITY_SERVICE` alone |
| Hardcoding the signing pin in Kotlin source | Inject via the baseline plugin/Gradle property; also verify natively |
| Killing the process on detection | Hands the attacker a breakpoint — degrade later and elsewhere |
| Requesting `QUERY_ALL_PACKAGES` | Use `<queries>`; expect Play rejection otherwise |
| Assuming the client verdict is trustworthy | Verify server-side |
