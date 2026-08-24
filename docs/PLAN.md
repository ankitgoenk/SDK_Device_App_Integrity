# Plan of Action

**Goal:** ship a production-grade Android SDK that detects (a) compromised device
environments — root, dynamic instrumentation, hooking frameworks, emulators, virtual
containers — and (b) threats to the integrity of the host app itself, including other
installed apps whose purpose is to modify, patch, observe or scramble it.

This document is the execution plan. Specifications live in the sibling documents linked
from the [README](../README.md).

---

## 0. Decisions to lock before coding

These block Phase 1. Answer them, record each as an ADR in [`adr/`](adr/).

| # | Decision | Default recommendation |
| --- | --- | --- |
| D1 | `minSdk` | **24** (Android 7.0). 21–23 costs disproportionate native/ART special-casing |
| D2 | Language / build | Kotlin 2.x, AGP 8.x, Gradle KTS, NDK r27 for the native core |
| D3 | Distribution | Maven artifacts (`integrity-core` + optional detector modules), AAR, published to a private Maven first |
| D4 | Dependency budget | Zero third-party runtime deps in `integrity-core` beyond kotlinx-coroutines and `androidx.annotation` |
| D5 | Native core | Yes — hooking/memory checks are not credible in Java only. C++17, `arm64-v8a`, `armeabi-v7a`, `x86_64` |
| D6 | Play Integrity | Optional module; SDK works without it, is far stronger with it |
| D7 | Telemetry | SDK ships **no** network stack. Host provides a `ReportSink`. Removes a whole class of privacy/policy risk |
| D8 | Package/namespace | Placeholder `io.integrity.*`, artifact group `io.integrity.sdk`. Rename before first release |
| D9 | Enforcement | SDK never terminates the process. Host decides. Documented "response cookbook" instead |
| D10 | Licence & OSS posture | Decide public vs. internal *before* Phase 8 — public source materially weakens self-protection |

---

## 1. Phase plan

Estimates assume one experienced Android engineer, with ~0.5 engineer of native/security
support from Phase 3. Phases 2–6 are largely parallelisable across two engineers.

### Phase 0 — Repository scaffold *(3–5 days)*
- Gradle multi-module skeleton exactly as in [ARCHITECTURE.md](ARCHITECTURE.md#module-layout).
- `sample-app` (a deliberately boring app that renders a live report) and `sample-backend`
  stub for verification.
- CI: assemble, unit tests, ktlint/detekt, API-compatibility check (`binary-compatibility-validator`),
  Android Lint, `connectedAndroidTest` on a Gradle-managed emulator device.
- `SessionStart`/dev-container setup so the build works from a clean clone.
- **Exit:** `./gradlew build` green in CI; sample app installs and shows an empty report.

### Phase 1 — Core engine and public API *(1–2 weeks)*
- Data model: `Signal`, `SignalId`, `Category`, `Confidence`, `Evidence`, `IntegrityReport`,
  `Verdict`. See [API_DESIGN.md](API_DESIGN.md).
- `Detector` SPI + `DetectionEngine`: parallel execution, per-detector timeout, crash
  isolation, `INCONCLUSIVE` degradation, result cache with TTL, depth tiers
  (`QUICK` / `STANDARD` / `FULL`).
- Risk scoring engine and `Policy` configuration ([RISK_SCORING.md](RISK_SCORING.md)).
- `ReportSink` SPI; in-memory and logcat sinks for development.
- **Exit:** engine runs 3 fake detectors, scoring is unit-tested to 90%+, `QUICK` pass
  measured under 20 ms on a mid-tier device.

### Phase 2 — Root & privileged-environment detection *(1 week)*
Signals `ROOT_*` in [DETECTION_CATALOG.md](DETECTION_CATALOG.md#1-root--privileged-environment).
Covers su/busybox/Magisk/KernelSU/APatch artefacts, manager packages, dangerous
properties, SELinux state, verified-boot state, mount-table anomalies, and native
`__system_property_get` vs. `getprop` divergence (resetprop detection).
- **Exit:** true positive on Magisk (with DenyList on and off) and KernelSU test devices;
  zero positives across the clean-device matrix in [TESTING.md](TESTING.md).

### Phase 3 — Hooking & instrumentation detection *(2–3 weeks, hardest phase)*
Signals `HOOK_*`. JVM layer (stack-trace probes, Xposed classes/artefacts, `TracerPid`,
debugger flags) plus the **native** layer: `/proc/self/maps` and thread-name scanning,
Frida port/handshake probe, memory scan for agent fingerprints, function-prologue and
PLT/GOT integrity checks on critical libc/libart symbols, ArtMethod anomaly checks.
- Build the native core (`integrity-native`) here: JNI bridge, string obfuscation,
  no exported symbols beyond the single entry point.
- **Exit:** detects `frida-server` (default and randomised port/name), `frida-gadget`
  embedded and injected, LSPosed module active, and a Java-method inline hook.

### Phase 4 — App integrity & tamper detection *(1 week)*
Signals `APP_*`. Signing-certificate pinning with rotation-lineage support, package name,
install source, per-`classes.dex` CRC/digest verification against build-time baked values,
native library digests, unexpected `DexPathList` entries, dynamically loaded code from
world-writable paths, debuggable flag.
- Gradle plugin task to compute and inject the build-time baseline
  (`integrity-baseline-plugin`) so digests are never hand-maintained.
- **Exit:** repackaged/re-signed sample APK is detected; Play App Signing rotation does not
  false-positive; split APKs / Play Feature Delivery handled.

### Phase 5 — Hostile-app & environment detection *(1 week)*
Signals `ENV_*`. Scoped, allow-listed `<queries>` probes for patchers (Lucky Patcher),
memory editors (GameGuardian), MITM proxies (HttpCanary et al.), cloners/virtual spaces,
Xposed/Magisk managers, and `frida-server` drops in `/data/local/tmp`. Plus ADB/developer
options, user-installed CA certificates, active VPN, screen overlays
(`FLAG_WINDOW_IS_OBSCURED`), MediaProjection, and non-allow-listed accessibility services.
- **Package visibility is the hard constraint here** — Android 11+ filtering and Google
  Play's `QUERY_ALL_PACKAGES` policy. Design in
  [INTEGRATION.md](INTEGRATION.md#package-visibility-android-11) and
  [PRIVACY_AND_COMPLIANCE.md](PRIVACY_AND_COMPLIANCE.md).
- **Exit:** curated hostile-package list detected on a test device with `<queries>` declared;
  behaviour is graceful (no signal, not a false negative claim) when visibility is denied.

### Phase 6 — Emulator, cloud phone & virtual container detection *(1 week)*
Signals `EMU_*` and `VIRT_*`: build/property fingerprints, QEMU device nodes, sensor and
telephony sanity, CPU/ABI translation, plus virtualised-container detection (process name
vs. package, data-path/UID anomalies, foreign package paths in maps, parent process not
zygote).
- **Exit:** AVD, Genymotion, redroid and a Parallel-Space-style clone all detected; work
  profile and legitimate multi-user do **not** trigger `VIRT_*`.

### Phase 7 — Attestation & server verification *(1.5 weeks)*
- `integrity-attestation-play`: Play Integrity **Standard** requests on the hot path,
  **Classic** for high-value actions; verdicts mapped into the signal model.
- Report signing: HMAC/ECDSA over the canonicalised report + server nonce, key material
  derived in native code; replay and clock-skew protection.
- `sample-backend`: nonce issuance, token verification, decision endpoint, and a worked
  example of combining SDK evidence with Play Integrity verdicts.
- **Exit:** end-to-end demo — tampered client's report is rejected server-side.

### Phase 8 — Self-protection & hardening *(1 week)*
See [ANTI_TAMPER.md](ANTI_TAMPER.md). R8 rules, string/constant obfuscation, control-flow
redundancy, no single kill-switch boolean, detection/response decoupling, integrity checks
on the SDK's own code, tamper-evident result objects.
- **Exit:** documented bypass cost; the obvious `frida -l bypass.js` one-liners against the
  public API no longer work without patching multiple independent paths.

### Phase 9 — Performance, stability & battery *(1 week)*
- Budgets: `QUICK` ≤ 20 ms main-thread-free, `STANDARD` ≤ 150 ms, `FULL` ≤ 1 s, all off the
  main thread; ≤ 3 MB retained heap; no wakelocks; no background polling by default.
- Macrobenchmark for cold-start delta; StrictMode clean; ANR/crash canaries; memory-leak
  checks; graceful behaviour with 200+ concurrent evaluate() calls.
- **Exit:** benchmark suite in CI with regression thresholds.

### Phase 10 — Validation & red teaming *(continuous from Phase 3, 1 week dedicated)*
Device matrix, rooted/Frida rigs, and an internal bypass exercise where an engineer who did
not write a detector tries to defeat it and writes up the cost. See [TESTING.md](TESTING.md).
- **Exit:** every catalogued signal has a passing positive test, a negative test, and a
  documented known-bypass entry.

### Phase 11 — Packaging & release *(1 week)*
Maven publication, semantic versioning, API stability policy, R8/consumer rules shipped in
the AAR, changelog, migration guide, licence decision, sample app polish, integration
documentation review.
- **Exit:** `1.0.0-rc1` consumed by a real host app from the artifact repository.

---

## 2. Timeline summary

| Phase | Work | Duration | Depends on |
| --- | --- | --- | --- |
| 0 | Scaffold | 3–5 d | — |
| 1 | Core engine + API | 1–2 w | 0 |
| 2 | Root detection | 1 w | 1 |
| 3 | Hooking / Frida | 2–3 w | 1 |
| 4 | App tamper | 1 w | 1 |
| 5 | Hostile apps / environment | 1 w | 1 |
| 6 | Emulator / virtual space | 1 w | 1 |
| 7 | Attestation + backend | 1.5 w | 1, 4 |
| 8 | Self-protection | 1 w | 2–7 |
| 9 | Performance | 1 w | 2–7 |
| 10 | Validation / red team | 1 w dedicated | 2–8 |
| 11 | Release | 1 w | all |

**Critical path ≈ 11–13 weeks solo; ≈ 7–8 weeks with two engineers** (2/4/5/6 in parallel
with 3).

### Suggested delivery increments
- **M1 "Signal"** — Phases 0–2: engine + root detection, consumable by an internal app.
- **M2 "Instrument"** — Phase 3: the differentiating capability.
- **M3 "Tamper"** — Phases 4–6: full client-side coverage.
- **M4 "Verify"** — Phases 7–8: server-side leverage and hardening; the first release you
  should actually rely on for anti-fraud decisions.
- **M5 "1.0"** — Phases 9–11.

---

## 3. Work breakdown checklist

### Phase 0
- [ ] `settings.gradle.kts` with all modules; version catalog (`gradle/libs.versions.toml`)
- [ ] Convention plugins (`build-logic/`) for android-library and native modules
- [ ] `sample-app` with a report screen
- [ ] CI workflow: build, unit test, lint, detekt, API dump check, instrumented smoke test
- [ ] `CODEOWNERS`, PR template, issue templates

### Phase 1
- [ ] `Signal`, `SignalId` (stable string IDs, never renumbered), `Category`, `Confidence`
- [ ] `Detector` SPI: `id`, `category`, `depth`, `cost`, `suspend fun detect(ctx): List<Signal>`
- [ ] `DetectionEngine`: parallel dispatch, per-detector timeout, `runCatching` isolation
- [ ] `ReportCache` with TTL + invalidation on process/lifecycle events
- [ ] `Policy` + `RiskScorer` + `Verdict`
- [ ] `IntegrityGuard` facade, thread-safe init, idempotent
- [ ] Java interop check (`@JvmStatic`, callback variant of the suspend API)

### Phase 2–6
- [ ] One PR per signal family, each with: implementation, unit tests, an instrumented test,
      a catalog entry, and an FP analysis
- [ ] Each detector registers a `SignalId` documented in `DETECTION_CATALOG.md` (CI fails if
      a `SignalId` exists in code with no catalog entry)

### Phase 7–8
- [ ] `integrity-attestation-play` behind an optional dependency
- [ ] Canonical report serialisation (stable, versioned) + signing
- [ ] Nonce protocol and replay window
- [ ] `sample-backend` with verification and a decision matrix
- [ ] Consumer R8 rules; obfuscation build step; hardening review

### Phase 9–11
- [ ] Macrobenchmark + regression gates
- [ ] Device-matrix run signed off
- [ ] Red-team write-up with per-signal bypass cost
- [ ] Publishing pipeline, versioning policy, changelog, licence

---

## 4. Risks and mitigations

| Risk | Impact | Mitigation |
| --- | --- | --- |
| **False positives lock out real users** | Revenue and support cost; the top risk | Shadow mode first (report, never enforce), per-signal FP analysis, allowlists, staged rollout with a remote kill switch per signal |
| **Google Play policy rejection** (`QUERY_ALL_PACKAGES`, accessibility scanning) | Cannot ship | Explicit `<queries>` list only; never request `QUERY_ALL_PACKAGES`; document data safety; see PRIVACY doc |
| **Package-visibility filtering** silently blinds `ENV_*` checks | False negatives read as "clean" | Model visibility as a capability; emit `INCONCLUSIVE`, never "absent → clean" |
| **Client-side checks bypassed** | Detection value decays | Server-side verification + Play Integrity as the backbone; treat client signals as risk input, not truth |
| **Detector hangs / ANRs** (`/proc` walks, socket probes) | Host app crashes; SDK gets removed | Hard per-detector timeouts, no main-thread IO, cancellation-aware coroutines, crash isolation |
| **OEM ROM diversity** (Xiaomi, Samsung, Huawei, Transsion) | Unpredictable FPs | Broad device matrix, property-based allowlists, telemetry-driven tuning in shadow mode |
| **Vendored detection heuristics rot** | Signals go stale | Version signal definitions; quarterly review; remote-tunable weights |
| **Legal/privacy exposure** from installed-app data | Compliance risk | Data minimisation: report hashed signal IDs, not app inventories; host owns the network |
| **Native crashes across ABIs** | Hard crashes in host apps | Fuzz `/proc` parsers, guard all pointer work, wrap native entry in a watchdog, per-ABI CI |

---

## 5. Open questions for the product owner

1. What is the **enforcement appetite**? Block, degrade, step-up auth, or observe only?
2. Is there a backend to receive reports, or must v1 be client-only? (Materially changes
   Phase 7's value.)
3. Is the app on Google Play with Play Services available in all target markets? (China /
   sideload markets lose Play Integrity — a second attestation path may be needed.)
4. Which host apps are the first integrators, and what is their `minSdk` and ABI set?
5. Public open source or internal? (D10 — affects Phase 8 substantially.)
6. Is a work-profile / dual-app / cloned-app user a legitimate user for this product?
