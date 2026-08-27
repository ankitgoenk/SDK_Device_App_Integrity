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
| D6 | ~~Play Integrity~~ | **Out of scope (ADR-0008).** The integrator runs their own attestation and combines its result with our evidence finding |
| D7 | Telemetry | SDK ships **no** network stack. Host provides a `ReportSink`. Removes a whole class of privacy/policy risk |
| D8 | Package/namespace | Placeholder `io.integrity.*`, artifact group `io.integrity.sdk`. Rename before first release |
| D9 | Enforcement | SDK never terminates the process. Host decides. Documented "response cookbook" instead |
| D10 | Licence & OSS posture | Decide public vs. internal *before* Phase 8 — public source materially weakens self-protection |
| D11 | Weight promotion | Blocked by two gates: report signing shipped, and a fraud-outcome join identified. See "Weight promotion" at the end of §1 |
| D12 | Fraud-outcome data | **Open.** Owning team, join key, outcome latency and retention must be recorded before shadow-mode ingestion starts |

---

## 1. Phase plan

Estimates assume one experienced Android engineer, with ~0.5 engineer of native/security
support from Phase 3. Phases 2–6 are largely parallelisable across two engineers.

### Phase 0 — Repository scaffold *(3–5 days)* — **DONE**
- Gradle multi-module skeleton exactly as in [ARCHITECTURE.md](ARCHITECTURE.md#module-layout).
- `sample-app` (a deliberately boring app that renders a live report) and `sample-backend`
  stub for verification.
- CI: assemble, unit tests, ktlint/detekt, API-compatibility check (`binary-compatibility-validator`),
  Android Lint, `connectedAndroidTest` on a Gradle-managed emulator device.
- `SessionStart`/dev-container setup so the build works from a clean clone.
- **Exit:** `./gradlew build` green in CI; sample app installs and shows an empty report.

> **Status: verified in CI.** All five jobs green on PR #1 (run 4, commit `404eed7`):
> catalog, static analysis, `apiCheck`, `assemble`+unit tests+lint, and the instrumented
> smoke test — the last one reporting `Starting 3 tests on emulator-5554 - 14` /
> `Finished 3 tests`, so the SDK demonstrably initialises and answers on a real Android 14
> runtime.
>
> **Evidential strength is not enforcement authority.** Later phases make signals harder to
> bypass; they do not make them fit to block a user. Every detection signal ships
> `INFORMATIONAL` regardless of which layer produced it, and only shadow-mode data plus
> server-side re-scoring promote it. A native check is better *evidence* than a JVM one —
> it is not permission to act on that evidence.
>
> Getting there took four rounds, each a distinct real defect rather than a flake:
> a missing API baseline; a ktlint code-style mismatch plus five detekt findings; an AAPT
> failure from referencing a Material Components XML theme the sample does not depend on;
> and finally an API dump generated without `-Xjvm-default=all` plus the ktlint Gradle
> plugin's configuration-cache incompatibility. Two of those were only reachable by running
> a real Android build, and one only by running the real Gradle plugins.

### Phase 1 — Core engine and public API *(1–2 weeks)* — **DONE**
- Data model: `Signal`, `SignalId`, `Category`, `Confidence`, `Evidence`, `IntegrityReport`,
  `Verdict`. See [API_DESIGN.md](API_DESIGN.md).
- `Detector` SPI + `DetectionEngine`: parallel execution, per-detector timeout, crash
  isolation, `INCONCLUSIVE` degradation, result cache with TTL, depth tiers
  (`QUICK` / `STANDARD` / `FULL`).
- Risk scoring engine and `Policy` configuration ([RISK_SCORING.md](RISK_SCORING.md)).
- `ReportSink` SPI; in-memory and logcat sinks for development.
- **Exit:** engine runs 3 fake detectors, scoring is unit-tested to 90%+, `QUICK` pass
  measured under 20 ms on a mid-tier device.

> **Status.** Engine, scoring, policy and cache are implemented and covered by 38 unit
> tests (17 of them on the scorer alone, one per documented rule). The instrumented tests
> confirm the engine dispatches a registered detector and reports full coverage on a real
> device. The `QUICK` timing target is **not** measured yet — that needs the macrobenchmark
> from phase 9, and there is no point benchmarking an engine with no real detectors in it.

### Phase 2 — Root & privileged-environment detection *(1 week)* — **IN PROGRESS**
Signals `ROOT_*` in [DETECTION_CATALOG.md](DETECTION_CATALOG.md#1-root--privileged-environment).
Covers su/busybox/Magisk/KernelSU/APatch artefacts, manager packages, dangerous
properties, SELinux state, verified-boot state, mount-table anomalies, and native
`__system_property_get` vs. `getprop` divergence (resetprop detection).
- **Exit:** true positive on Magisk (with DenyList on and off) and KernelSU test devices;
  zero positives across the clean-device matrix in [TESTING.md](TESTING.md).

> **Status.** First slice landed: `ROOT_SU_BINARY`, `ROOT_MANAGER_PACKAGE` and
> `ROOT_DANGEROUS_PROPS`, JVM layer only, 22 unit tests, each with a catalog row stating
> technique, false-positive risk and known bypass (enforced by CI).
>
> Be clear about what this buys: **all three are defeated by a hidden Magisk install.**
> DenyList unmounts the artefacts, the manager repackages under a random name, and
> `resetprop` rewrites the build tags. They catch careless setups and generate shadow-mode
> evidence; they are not a root check anyone should enforce on. The signals with teeth —
> mount-table divergence, property spoofing, verified-boot state — need the native core in
> phase 3, and the authoritative answer is Play Integrity server-side in phase 7.
>
> All three ship at `INFORMATIONAL` per hard rule 6, so they contribute nothing to the score
> until a host opts in via `RootDetectors.proposedWeights(policy)`. An instrumented test
> asserts that end-to-end.
>
> Still open for phase 2: property/mount signals, `ROOT_KERNELSU`, `ROOT_APATCH`,
> `ROOT_SELINUX_PERMISSIVE`, `ROOT_RW_SYSTEM`, `ROOT_UID_ZERO`, and the rooted-device test
> rigs from [TESTING.md](TESTING.md), which no CI emulator can substitute for.

### Phase 2 leftovers

- [ ] `integrity-detector-root` has no direct positive instrumented control: the
      dirty-image direction is currently proven only via `sample-app`. Give the module its
      own self-contained pair (clean image → no signal, dirty image → expected signal) with
      the next root slice, so the detector's test suite does not depend on another module
      to show it works.

### Phase 3a — Native walking skeleton *(2–3 days)* — **DONE**

> **Status:** implemented. First CI runs with the NDK produced the shipped sizes below —
> arm64-v8a 219 KB, armeabi-v7a 125 KB, x86_64 207 KB, against a 256 KB budget. Almost all
> of that is the static libc++ pulled in by `ANDROID_STL=c++_static`, which the JNI
> boundary needs in order to catch C++ exceptions rather than let them escape into the
> host app. Phase 3b adds real detection logic to a library already close to budget, so
> either the budget moves with a stated reason or the exception-based containment gets
> replaced with error codes and `-fno-exceptions`. Decide before writing 3b, not after.

The temptation is to open `integrity-native` and write four thousand lines of anti-Frida
machinery before finding out whether the `.so` even loads on a consumer's device. This
phase exists to stop that. It ships **one trivial native function** and proves the whole
delivery path around it.

Exit criteria — every one of these is a CI assertion, not a manual check:

1. NDK build succeeds for `arm64-v8a`, `armeabi-v7a` and `x86_64`.
2. The AAR packages the `.so` for every ABI.
3. The emulator loads it and the JNI call returns a value.
4. That value reaches the Kotlin engine as a real `Signal`.
5. R8 with the shipped consumer rules does not break loading.
6. `sample-consumer` loads it from the **published AAR**, not a project dependency.
7. Deliberately breaking the load produces `META_NATIVE_UNAVAILABLE` and
   `Confidence.INCONCLUSIVE` — never a silent "clean".
8. A native failure cannot crash the host: the JNI entry point is wrapped and a forced
   failure is exercised on-device.
9. `nm`/`readelf` confirm the release `.so` is stripped and exports no `Java_io_integrity_*`
   symbols, so the ADR-0002 claim is tested rather than asserted.
10. Per-ABI `.so` size is within the budget recorded in phase 9 (≤ 250 KB).

**Decision this phase must settle:** `META_NATIVE_UNAVAILABLE` currently carries `HIGH`
weight and a score floor of 50. It is inert today because no native library ships. The
moment one does, every device where the `.so` fails to load — unusual ABI, aggressive
repackaging tooling, `extractNativeLibs` interactions — becomes `SUSPICIOUS`. Before
enabling the native module by default, measure how often loading genuinely fails and decide
whether that weight survives contact with real devices. This is the one place where the
SDK's own robustness problem masquerades as a device-integrity signal.

### Phase 3b prerequisites — settle these before writing detection code

**1. The size/exception trade — measured, decided, recorded.** Done. arm64-v8a release
stripped: 219,472 B with exceptions, 217,944 B without `<stdexcept>`, 5,528 B with
`STL=none -fno-exceptions`. Dropping `<stdexcept>` saves 0.7%; the cost is exception
support itself. ADR-0005 adopts the third option and defines the failure model that
replaces it. **Implement the failure model before flipping the build configuration** —
otherwise the change reads as "we removed the safety net" rather than "we replaced it with
one that covers the hazard we actually have".

Order of work:

1. Native status contract and validated reads (ADR-0005 points 1–4).
2. Replace `provokeFailure()` with a malformed-`/proc` fixture driving the real parser.
3. CI proves the failure model: bad input yields a status code, the host survives.
4. Only then switch to `STL=none -fno-exceptions`, and re-verify AAR, emulator, consumer.
5. Only then the first `HOOK_*` detector.

**2. Make `APP_NATIVE_LIB_MISMATCH` diagnosable.** Report the expected and actual tokens.
They are SDK version strings, not secrets, and an attacker reads them out of the `.so`
anyway. Without them a mismatch cannot be told apart from a dependency-skew bug in the
host's build, which is the likeliest cause by far.

### Phase 3b — Hooking & instrumentation detection *(2–3 weeks, hardest phase)* — **IN PROGRESS**

Start with **one** capability carried all the way through — signal, clean fixture, positive
fixture, known bypass, CI, shadow mode — before adding a second. The catalog lists eighteen
`HOOK_*` signals; building them as a batch would reproduce exactly the failure phase 3a was
created to avoid, with detection bugs and infrastructure bugs arriving together.
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

### Phase 7 — Server verification *(1.5 weeks)* — **IN PROGRESS**
- **No attestation.** ADR-0008 removed it from this project's scope: the integrator already
  runs Play Integrity end to end and combines its result with our finding. The `ATT_*` signals
  stay in the vocabulary as `SRV` — the identifiers under which an integrator feeds their own
  attestation verdict into `RiskScorer`, never produced by a detector here.
- Report signing: HMAC/ECDSA over the canonicalised report + server nonce, key material
  derived in native code; replay and clock-skew protection.
- `sample-backend`: nonce issuance, single-use redemption, and server-side re-scoring that
  reports what the evidence supports.
- **Exit:** end-to-end demo — tampered client's report is rejected server-side.

> **Done ahead of order** (PRs #20, #21), because the client half of ADR-0006 needed a
> counterpart to be worth anything: challenge issuance and single-use redemption bound to a
> session and purpose; the evidence pipeline; server-authoritative freshness. ADR-0007 came
> out of it, and ADR-0008 then reshaped the output vocabulary to
> `COMPROMISED / NO_EVIDENCE_OF_COMPROMISE / INSUFFICIENT_EVIDENCE` with no access action at
> all, because with attestation gone there is nothing that could honestly produce one.
>
> **Left in this phase:** report signing, and parsing the canonical wire form server-side.

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

### Weight promotion — two gates that block it

Hard rule 6 ships every signal at `INFORMATIONAL`, so today no detector can move a verdict on
its own. Promoting one above zero is the moment this stops being an engineering exercise and
becomes a fraud-risk decision. Two things must be true first. Neither is negotiable by
whoever happens to be promoting the signal.

**Gate 1 — report signing must exist before the first non-zero weight.**

Shadow mode may run on unsigned reports, and that is not an oversight. While every weight is
zero, no decision depends on a report, so nobody has an incentive to forge one; the data is
trustworthy because it is worthless to fake. That changes the instant a weight goes above
zero. From then on a stripped SDK posting a syntactically valid empty report earns
`NO_EVIDENCE_OF_COMPROMISE` — the same finding a healthy device earns — and that is a bypass
worth building.

So the gate is not "signing comes third in the roadmap", it is a precondition on promotion:
**no weight may exceed `INFORMATIONAL` until report signing is implemented and verified.**

State its limit precisely wherever it ships, because the obvious reading is too generous:
signing defends against SDK **removal**, not SDK **subversion**. A patched client that still
signs produces byte-identical output to an honest one, so ADR-0007 stands unamended and a
signed report is still not exoneration.

**Gate 2 — prevalence is not evidence. The fraud-outcome join is a hard dependency.**

Knowing that `ROOT_SU_BINARY` fires on 3% of sessions says nothing about whether those
sessions are fraudulent. Promotion needs integrity reports joined to authoritative fraud
outcomes — chargebacks, confirmed account-takeover, manual-review verdicts — and that is a
dependency on systems this project does not own. Identify it now; it has a longer lead time
than the code.

Record, before shadow-mode ingestion begins:

| What | Why it blocks promotion |
| --- | --- |
| Owning system and team for each outcome source | Nobody can produce the join without them |
| The join key, and which side supplies it | See the constraint below — it is not ours |
| Outcome latency (a chargeback can land 90+ days after the session) | Sets the minimum shadow window, and may exceed the retention period |
| Raw-report retention period and its owner | `PRIVACY_AND_COMPLIANCE.md` recommends <= 90 days and P6 puts retention with the host; recommended is not adopted |

**The join key is not ours to supply, and must not become ours.** `IntegrityReport` carries
`reportId`, `sdkVersion`, `depth`, `coverage`, `signals`, `generatedAtMillis` and `challenge` —
and deliberately no stable device identifier, because hard rule 3 forbids IMEI, `ANDROID_ID`,
MAC and location, and hashes third-party package names. There is nothing in our evidence to
join on *by design*. The key comes from the host's own session or account context. The
tempting fix when the join proves awkward is to add a device identifier to the report; that
breaks hard rule 3 and must be refused.

**Judge a signal on precision at its operating point, not on two rates in isolation.** "Fires
on 80% of fraudulent devices and 0.2% of legitimate ones" sounds decisive and frequently is
not. At a 0.1% fraud rate across 100,000 sessions that is 80 true positives against ~200 false
ones: **precision 29%, so seven in ten flagged users are innocent.** Hard rule 9 makes that
pure cost — evidence can only incriminate, so a wrong detection has no offsetting benefit to
trade against. The promotion criterion is the precision the business will actually accept at
the action being gated, which differs between a balance check and a withdrawal.

---

## 2. Timeline summary

| Phase | Work | Duration | Depends on |
| --- | --- | --- | --- |
| 0 | Scaffold | 3–5 d | — |
| 1 | Core engine + API | 1–2 w | 0 |
| 2 | Root detection | 1 w | 1 |
| 3a | Native walking skeleton | 2–3 d | 1 |
| 3b | Hooking / Frida | 2–3 w | 3a |
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
- [x] `settings.gradle.kts` with all modules; version catalog (`gradle/libs.versions.toml`)
- [x] Convention plugins (`build-logic/`) for android-library, application and JVM modules
- [x] `sample-app` with a report screen
- [x] CI workflow: build, unit test, lint, detekt, ktlint, API check, catalog check, instrumented smoke test
- [x] `CODEOWNERS`, PR template
- [x] `tools/check-signal-catalog.py` — CI gate tying every `SignalId` to a catalog row
- [x] `tools/setup-dev-env.sh` + `SessionStart` hook for clean-clone/web sessions
- [x] `./gradlew build` verified green in CI
- [x] Committed `api/*.api` surface, enforced by `apiCheck`
- [x] Instrumented smoke test executing on an emulator (3 tests, API 34)
- [x] `sample-consumer`: consumes a **published AAR** from a local Maven repo, exercising
      AAR packaging, consumer ProGuard rules under R8, manifest merging and the ADR-0004
      `<queries>` fragment — with CI asserting `QUERY_ALL_PACKAGES` never appears
- [x] Evidence-chain CI gate (`tools/check-signal-catalog.py`)
- [ ] Issue templates (deferred; not a phase 0 blocker)

**Phase 0 is closed.** Run 7 of CI on PR #1 was green across all six jobs, with
`Starting 4 tests` / `Starting 3 tests` on an Android 14 emulator for `sample-app` and
`sample-consumer` respectively — so both the project-dependency and published-AAR paths are
verified on a real runtime, not merely built.

### Phase 1
- [x] `Signal`, `SignalId` (stable string IDs, never renumbered), `Category`, `Confidence`
- [x] `Detector` SPI: `id`, `category`, `minDepth`, `budget`, `suspend fun detect(ctx)`
- [x] `DetectionEngine`: parallel dispatch, per-detector timeout, crash isolation
- [x] `ReportCache` with per-depth TTL
- [x] `Policy` + `Weight` + `RiskScorer` + `Verdict`, incl. every documented escalation rule
- [x] `IntegrityGuard` facade, thread-safe init, idempotent, `reports()` flow
- [ ] Cache invalidation on package-changed / foreground-after-gap events
- [ ] Java interop check (callback variant of the suspend API, `Cancellable`)
- [ ] `QUICK` pass measured under 20 ms (needs the phase 9 macrobenchmark)

### Phase 2–6
- [ ] One PR per signal family, each with: implementation, unit tests, an instrumented test,
      a catalog entry, and an FP analysis
- [ ] Each detector registers a `SignalId` documented in `DETECTION_CATALOG.md` (CI fails if
      a `SignalId` exists in code with no catalog entry)

### Phase 7–8
- [ ] Canonical report serialisation (stable, versioned) + signing — **gates all weight promotion**
- [ ] Nonce protocol and replay window
- [ ] `sample-backend` parsing the canonical wire form and verifying report signatures
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
| **False positives lock out real users** | Revenue and support cost; the top risk | Shadow mode first (report, never enforce), per-signal FP analysis, allowlists, staged rollout with a remote kill switch per signal. Promote on **precision at the operating point**, never on hit rate: at a 0.1% fraud rate, 80% recall with a 0.2% false-positive rate is still 29% precision |
| **Google Play policy rejection** (`QUERY_ALL_PACKAGES`, accessibility scanning) | Cannot ship | Explicit `<queries>` list only; never request `QUERY_ALL_PACKAGES`; document data safety; see PRIVACY doc |
| **Package-visibility filtering** silently blinds `ENV_*` checks | False negatives read as "clean" | Model visibility as a capability; emit `INCONCLUSIVE`, never "absent → clean" |
| **Client-side checks bypassed** | Detection value decays | Server-side re-scoring; treat client signals as risk input, never as truth. The integrator's attestation is the backbone, and it is theirs (ADR-0008) |
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
7. **Which team owns the fraud outcomes** (chargebacks, confirmed ATO, manual review), what
   join key can they supply, and how long after a session does an outcome land? Blocks D11.
8. Who owns the raw-report retention decision, and is the recommended <= 90 days compatible
   with the outcome latency in (7)? A 90-day window and a 120-day chargeback do not join.
