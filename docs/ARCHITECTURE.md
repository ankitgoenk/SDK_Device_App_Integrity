# Architecture

## Overview

```
┌──────────────────────────────────────────────────────────────┐
│ Host application                                             │
│   IntegrityGuard.initialize(...) / evaluate(...)             │
└───────────────┬──────────────────────────────────────────────┘
                │  public API (integrity-core:api)
┌───────────────▼──────────────────────────────────────────────┐
│ DetectionEngine                                              │
│  • detector registry      • depth tiers (QUICK/STANDARD/FULL)│
│  • parallel dispatch      • per-detector timeout + isolation │
│  • result cache (TTL)     • signal deduplication             │
└───────┬──────────────────────────────────────────────────────┘
        │ Signal[]
┌───────▼───────────┐   ┌──────────────┐   ┌───────────────────┐
│ RiskScorer/Policy │──▶│IntegrityReport│──▶│ ReportSink (host) │
└───────────────────┘   └──────────────┘   └───────────────────┘
        ▲
        │ Detector SPI
┌───────┴──────────────────────────────────────────────────────┐
│ Detector modules                                             │
│  root │ hooking │ app-tamper │ environment │ emulator │ play │
└───────┬──────────────────────────────────────────────────────┘
        │ JNI
┌───────▼──────────────────────────────────────────────────────┐
│ integrity-native (C++): maps/thread scan, prologue & GOT     │
│ checks, property probes, memory fingerprints, string vault   │
└──────────────────────────────────────────────────────────────┘
```

## Module layout

| Module | Type | Contents |
| --- | --- | --- |
| `integrity-core` | android-library | Public API, data model, `DetectionEngine`, scoring, cache, `Detector`/`ReportSink` SPI. **No detectors.** |
| `integrity-native` | android-library + CMake | JNI core: `/proc` scanning, memory and code-integrity checks, obfuscated string vault. Single exported JNI entry point. |
| `integrity-detector-root` | android-library | `ROOT_*` signals |
| `integrity-detector-hooking` | android-library | `HOOK_*` signals (JVM half; delegates to `integrity-native`) |
| `integrity-detector-app` | android-library | `APP_*` signals: signature, dex/lib digests, classloader |
| `integrity-detector-environment` | android-library | `ENV_*` signals: hostile packages, ADB, CA store, overlays, a11y |
| `integrity-detector-emulator` | android-library | `EMU_*` and `VIRT_*` signals |
| `integrity-attestation-play` | android-library | Play Integrity wrapper, verdict mapping |
| `integrity-baseline-plugin` | gradle-plugin | Build-time baseline generation (dex/lib digests, signing pins, string obfuscation keys) |
| `integrity-testing` | android-library (debug) | Fakes, fixtures, a `ScriptedDetector` for host-app testing |
| `sample-app` | application | Live report UI, forced-signal playground |
| `sample-backend` | jvm | Nonce issuance, report verification, decision endpoint |

**Dependency rule:** detectors depend on `integrity-core`; `integrity-core` never depends on
a detector. Registration happens at init via explicit factories (no reflection, no
ServiceLoader — both are trivially strippable and slow).

```kotlin
IntegrityConfig.Builder()
    .detectors(RootDetectors.all() + HookDetectors.all() + AppDetectors.all())
```

This keeps the SDK tree-shakeable: an integrator who only wants root detection ships one
detector module.

## Execution model

- **Entry points:** `evaluate(depth)` (suspend) and `evaluateAsync(depth, callback)` for Java.
- **Dispatcher:** a dedicated bounded dispatcher (`Dispatchers.Default.limitedParallelism(4)`)
  so the SDK never starves the host's coroutines and never touches the main thread.
- **Depth tiers:**
  - `QUICK` — cached-only + O(1) property/flag checks. Target ≤ 20 ms. Safe per-screen.
  - `STANDARD` — filesystem probes, package queries, JVM hooking probes. Target ≤ 150 ms.
  - `FULL` — native memory/maps scans, socket probes, digest verification, attestation.
    Target ≤ 1 s. Call at app start, before high-value actions, or on a long interval.
- **Isolation:** each detector runs inside `withTimeoutOrNull(detector.budget)` +
  `runCatching`. Failure or timeout yields `Signal(INCONCLUSIVE)` with the reason; it never
  propagates to the host.
- **Caching:** results are cached per depth with a TTL (default 5 min for `FULL`, 60 s for
  `STANDARD`). Cache is invalidated on `ACTION_PACKAGE_ADDED` for watched packages, on
  process start, and on returning to foreground after a configurable gap.
- **Cancellation:** all `/proc` and socket work is cancellation-aware; a cancelled scope
  releases file descriptors deterministically.

## Signal flow

1. Detector produces `Signal(id, category, confidence, evidence, detectorVersion)`.
2. Engine tags each signal with collection metadata (duration, depth, tier).
3. `RiskScorer` applies `Policy` (weights, caps, category rules, allowlists) →
   `riskScore: Int (0..100)` + per-category subscores + `Verdict`.
4. `IntegrityReport` is assembled, frozen (immutable, `equals`-stable), and optionally
   canonicalised + signed for transport ([SERVER_VERIFICATION.md](SERVER_VERIFICATION.md)).
5. `ReportSink`s (host-provided) receive the report. The SDK performs no network IO.

## Why a native core

Java-only detection of Frida and inline hooking is not credible: the checks themselves are
the easiest thing in the process to hook. The native layer:

- reads `/proc/self/maps`, `/proc/self/task/*/comm`, `/proc/self/fd`, `/proc/self/status`
  without going through `java.io` (which is hookable at the ART level);
- verifies prologues of a small set of critical libc/libart symbols against expected
  instruction patterns and checks that PLT/GOT entries resolve inside their owning module;
- scans executable, non-file-backed regions for instrumentation fingerprints;
- holds the string vault (all detection literals XOR-obfuscated at build time by
  `integrity-baseline-plugin`) so `strings libapp.so` reveals nothing useful;
- computes report signatures with a key that never exists as a Java constant.

Native code is compiled with `-fvisibility=hidden`, `-ffunction-sections`, LTO, and full
symbol stripping; exactly one `JNI_OnLoad`-registered entry point is exposed, and it is
registered dynamically rather than by exported `Java_…` names.

## Threading and safety invariants

1. No main-thread file, socket or `PackageManager` IO — ever. Enforced by a StrictMode-based
   debug assertion and a lint rule.
2. No detector may allocate more than a bounded buffer for `/proc` reads (cap 1 MB, streamed).
3. Native code must not `abort()`; every entry point is wrapped, and parsing is fuzzed in CI.
4. The SDK holds no static reference to an `Activity`; only `applicationContext`.
5. Public API is safe to call before `initialize()` — it returns `Verdict.UNKNOWN` rather
   than throwing.

## Extensibility

- **Custom detectors:** hosts may register their own `Detector` implementations (e.g. a
  business-specific device check) and have them scored by the same policy.
- **Remote policy:** `Policy` is serialisable, so weights and per-signal enable flags can be
  fetched by the host from its own config service and applied without an SDK release. The SDK
  never fetches config itself.
- **Signal versioning:** each `SignalId` is a stable string (`ROOT_MAGISK_PATHS`). Renaming an
  ID is a breaking change; deprecate and add instead.
