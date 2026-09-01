# Testing & Validation Strategy

Detection code has an unusual property: a false negative is silent, and a false positive is a
support ticket from a paying customer. Both need deliberate testing.

## 1. Test pyramid

| Level | What | Where |
| --- | --- | --- |
| Unit | Parsers (`/proc/maps`, `/proc/mounts`, `/proc/net/unix`, property output), scoring, policy, canonical JSON | JVM, `integrity-*/src/test` |
| Fixture-driven | Real captured `/proc` dumps and `PackageManager` snapshots from rooted, Frida'd, emulated and clean devices | `integrity-testing/fixtures/` |
| Instrumented | Detector behaviour on a real Android runtime | `androidTest`, Gradle-managed devices |
| Device matrix | Full sweep across physical and virtual devices | Nightly, device farm |
| Red team | Human attempts to bypass | Per release |

**Fixtures are the backbone.** Capture once from a compromised device, replay forever in fast
JVM tests. Every parser bug found in the field becomes a fixture.

## 2. Positive-case rigs

| Rig | Setup | Signals it must trigger |
| --- | --- | --- |
| **Magisk (visible)** | Pixel-class device, unlocked bootloader, Magisk, DenyList off | Most `ROOT_*` |
| **Magisk (hidden)** | Same + DenyList/Zygisk on, manager repackaged | `ROOT_MOUNT_ANOMALY`, `ROOT_PROP_SPOOF`, `ATT_DEVICE_INTEGRITY_FAIL` |
| **KernelSU / APatch** | Custom kernel | `ROOT_KERNELSU` / `ROOT_APATCH` — **neither exists in code**. The rig is real (§9) and today triggers `ROOT_MANAGER_PACKAGE` only |
| **frida-server** | Default port, then randomised port + renamed binary | `HOOK_FRIDA_*` (at least maps/threads/memscan when the port probe fails) |
| **frida-gadget** | Injected into the sample APK | `HOOK_FRIDA_MAPS`, `APP_DEX_DIGEST_MISMATCH`, `APP_SIGNATURE_MISMATCH` |
| **LSPosed** | Zygisk module hooking the sample app | `HOOK_XPOSED_*`, `HOOK_ART_METHOD_ANOMALY` |
| **Repackaged app** | apktool rebuild, self-signed | `APP_SIGNATURE_MISMATCH`, `APP_DEX_DIGEST_MISMATCH`, `ATT_APP_NOT_RECOGNISED` |
| **Debugger** | `adb shell am set-debug-app`, lldb attach | `HOOK_DEBUGGER_ATTACHED`, `HOOK_TRACER_PID` |
| **Emulator** | AVD (Play and non-Play images), Genymotion, redroid | `EMU_*`, `ATT_VIRTUAL_ONLY` |
| **Virtual space** | Sample app cloned into a VirtualApp-style container | `VIRT_*` |
| **Hostile apps** | Lucky Patcher, GameGuardian, HttpCanary installed | `ENV_*` |

Keep these as **documented, reproducible setups** (scripts in `tools/rigs/`), not as tribal
knowledge on one engineer's spare phone.

> One of these rigs now exists and one clean device is paired with it. What they actually
> observed — rather than what this table says they should — is recorded in
> [§9](#9-measured-baseline--the-two-reference-devices).

## 3. Negative-case matrix (false positives)

Zero signals above `POSSIBLE` are permitted on any of these:

| Category | Devices |
| --- | --- |
| Mainstream flagships | Pixel (last 3 versions), Samsung One UI, OnePlus |
| Chinese OEM ROMs | Xiaomi HyperOS/MIUI, Oppo ColorOS, Vivo FuntouchOS, Honor MagicOS |
| Budget / emerging market | Transsion (Tecno/Infinix/itel), Realme, Moto low-tier |
| Special environments | Work profile (Android Enterprise), multi-user secondary user, ChromeOS ARC, Windows Subsystem for Android |
| Accessibility | TalkBack enabled, Switch Access enabled, high-contrast/magnification |
| Corporate | MDM-enrolled device with a user CA installed and an always-on VPN |
| Developer-ish but legitimate | ADB enabled, developer options on, app installed via `adb install` |
| OS versions | API 24 through the current preview |

For the last two rows, the requirement is not "no signals" but "no verdict above `LOW_RISK`
under `Policy.balanced()`".

> The Xiaomi entry in the Chinese-OEM row has been measured; see
> [§9](#9-measured-baseline--the-two-reference-devices). It produces no signal above
> `INCONCLUSIVE`.

## 4. CI

| Job | Trigger | Gate |
| --- | --- | --- |
| Build + unit tests + detekt/ktlint | Every PR | Must pass |
| API compatibility (`apiCheck`) | Every PR | Explicit review to change |
| Catalog consistency | Every PR | Every `SignalId` in code has a `DETECTION_CATALOG.md` row and vice versa |
| Instrumented smoke on GMD emulator | Every PR | Engine runs, no crash, `EMU_*` fires as expected |
| Native fuzzing (`/proc` parsers, libFuzzer) | Nightly | No crashes, no leaks under ASAN |
| Multi-ABI native build | Every PR | arm64-v8a, armeabi-v7a, x86_64 |
| Macrobenchmark | Nightly + release | Cold-start delta and per-depth budgets within thresholds |
| Device farm matrix | Nightly | FP matrix clean |
| Release APK size / method count | Release | Within budget (target < 400 KB AAR, < 250 KB native per ABI) |

## 5. Performance testing

| Metric | Budget | How |
| --- | --- | --- |
| Cold-start delta with `initialize()` | ≤ 5 ms | Macrobenchmark, Pixel 6a class |
| `QUICK` evaluate | ≤ 20 ms | Microbenchmark |
| `STANDARD` evaluate | ≤ 150 ms | Microbenchmark |
| `FULL` evaluate | ≤ 1 s | Microbenchmark; the memory scan dominates — cap regions scanned |
| Retained heap | ≤ 3 MB | LeakCanary + heap dump assertions |
| Battery | No measurable delta over a 1 h session | No polling by default |
| Main-thread violations | Zero | StrictMode in the sample app, failing the test on violation |

## 6. Red-team drill

Once per release, an engineer who did **not** write the detectors attempts, timeboxed to two
days:

1. Bypass root detection with public Frida scripts only.
2. Bypass with a custom script targeting the SDK's actual implementation.
3. Strip the native library.
4. Patch the scoring layer to always produce `NO_EVIDENCE_OF_COMPROMISE`.
5. Repackage and re-sign the sample app.
6. Replay a captured clean signed payload.
7. Run the app inside a cloner/virtual space.

Record per attack: time to bypass, number of independent changes required, and whether the
**backend** still detected it. Goal state: every client-side bypass leaves a server-visible
trace ([ANTI_TAMPER.md](ANTI_TAMPER.md#8-measuring-effectiveness)). File a defect for any
attack that succeeds end-to-end (client *and* server blind) with a single change.

## 7. Shadow-mode field validation

Before enforcement, an integrator runs `Policy.observability()` for a full release cycle. What
to look at:

- Score distribution overall and per `Build.MANUFACTURER`, OS version, locale, app version.
- Per-signal fire rate. A signal firing on > 2% of sessions is informational or broken.
- Correlation between signals (highly correlated signals should not double-count — cap the
  category).
- Correlation with known-fraud outcomes: does the score actually separate fraud from
  legitimate use? If a signal has no lift against ground truth, it is telemetry, not a
  control.
- Coverage distribution: how often is `INCONCLUSIVE` dominant, and why?

## 8. Regression policy

- Every field-reported false positive becomes a fixture plus a negative test before the fix
  merges.
- Every successful bypass becomes a new detection or an explicit, documented "won't detect"
  entry in the catalog with the rationale.
- Signal weights change only with data attached to the PR.

## 9. Measured baseline — the two reference devices

Everything in §2 and §3 above describes rigs that *should* exist. This section records the two
that **do**, and exactly what the SDK observed on them. Every cell below is a measured run, not
an expectation: a table of assumptions formatted like evidence is worse than no table.

Recorded **2026-08-31**, against `fix/native-self-text-and-visibility`.

| | Positive control | Clean control |
| --- | --- | --- |
| Device | Pixel 10a (`stallion`) | Xiaomi M2101K6I (`sweetin`) |
| Build | `google/stallion/stallion:16/CP1A.260505.005/15081906:user/release-keys` | MIUI, Android 13 (API 33) |
| State | **Rooted**: KernelSU Next (`com.rifsxd.ksunext`, `ksud 3.2.0`), custom kernel `6.1.145-android14-Wild`, modules `susfs4ksu` / `tricky_store` / `rezygisk` / `hma_oss_zygisk` | Stock, unmodified |

### What the SDK reported

With a signing pin configured, so every detector executes:

```
Pixel (rooted)          Verdict NO_EVIDENCE_OF_COMPROMISE   score 0/100   coverage 100%
                        • ROOT_MANAGER_PACKAGE [ROOT/LIKELY] {count=1}

Xiaomi (clean)          Verdict NO_EVIDENCE_OF_COMPROMISE   score 0/100   coverage 85%
                        • ROOT_MANAGER_PACKAGE [ROOT/INCONCLUSIVE] {reason=package_visibility_filtered}
                        • META_VISIBILITY_RESTRICTED [META/INCONCLUSIVE]
```

**A rooted device at full coverage with a correct positive detection still scores 0/100.** That
is hard rule 6 working as written — every signal ships `INFORMATIONAL` — and it is the reason
"coverage" and "detection" must never be reported as the same number. See "Two kinds of
coverage" below.

### Per-detector audit

| Detector | Observes exactly | Blind when | Pixel | Xiaomi |
| --- | --- | --- | --- | --- |
| `SuBinaryDetector` | 15 fixed paths, `File.exists()` | artefact renamed, outside the list, or **not in the app's mount namespace** | **blind** — `/system/bin/su` is visible to shell and `ENOENT` to the app | silent (0/15), correct |
| `RootManagerPackageDetector` | 7 package names, via `<queries>` | manager renamed, hidden by an app-list hider, or absent from the `<queries>` fragment | **LIKELY** — the only positive any detector produced | inconclusive (visibility) |
| `DangerousPropertiesDetector` | `Build.TAGS`, `Build.TYPE` | **any kernel-level root** — the system image stays stock | **blind** — genuinely `release-keys` / `user` | same values, correct silence |
| `SignatureDetector` | pinned cert vs current signers | no pin configured (its state in every earlier run) | ran, matched | ran, matched |
| `NativeIntegrityDetector` | library loads, self-token matches | library absent | silent | silent |
| `SelfTextDetector` | own `.text` vs its backing file | GOT/PLT redirection or ART entry-point swaps touch no `.text` | ran, clean | ran, clean |

`SignatureDetector` had never executed before this baseline; both devices had always reported
`no_pin_configured`. It was pinned to a debug certificate for the measurement and reverted,
because a debug cert is per-machine and would fail in CI.

### Results that are answers, not backlog

Measured on the Pixel, so nobody spends a spike re-deriving them:

- **Loader vs `/proc/self/maps`: no divergence.** Root's view and the app's own view of the
  same process were byte-identical (3471 lines, 815 distinct paths). Zygisk *is* mapped into
  `zygote64` (6 mappings) and absent from the forked child in **both** views — ReZygisk unloads
  itself rather than hiding. A `HOOK_MAPS_INCONSISTENT` detector has **no positive control on
  this hardware**; do not ship one until a divergence can be deliberately constructed.
- **Mount-table divergence: none.** `/proc/self/mounts` vs `/proc/1/mounts` — 154 vs 154, zero
  overlay mounts visible.
- **Property spoofing exists but is unreachable.** `/proc/bootconfig` says
  `androidboot.vbmeta.device_state = "unlocked"` and `verifiedbooterror = "ERROR_VERIFICATION"`
  while `ro.boot.vbmeta.device_state` reports `locked`. `/proc/bootconfig` is root-only and
  `/proc/cmdline` carries no vbmeta entries on Android 12+, so **an app cannot make this
  comparison**. Evidence that spoofing happens; not a detector. See `ROOT_PROP_SPOOF`.

### Attestation and cloaking, measured 2026-09-01

Recorded against `claude/android-security-detection-sdk-f3c8uh` @ `3f0f938`, same Pixel 10a.

**Play Integrity returns every tier on this rooted device.** Raw response, fresh nonce,
`requestPackageName: gr.nikolasspyr.integritycheck`:

```
"deviceRecognitionVerdict": [
    "MEETS_BASIC_INTEGRITY", "MEETS_DEVICE_INTEGRITY", "MEETS_STRONG_INTEGRITY"
]
```

`tricky_store` presents a leaked keybox and hardware-backed attestation accepts it. Read this
narrowly: it is **one device, one keybox, one moment** — Google revokes keyboxes, so this is
"a current keybox passes today", not "attestation is broken". It is still enough to retire the
claim that a failing `MEETS_DEVICE_INTEGRITY` is the most reliable root signal available, and
`ATT_DEVICE_INTEGRITY_FAIL` and ADR-0007's Consequences were corrected in the same PR.

**A configured cloaker defeats package visibility completely, including itself.**
`org.frknkrc44.hma_oss` (Hide My AppList) was already installed here and aimed at a banking
app, with 1722 requests filtered. Aiming its "Hide Root" template at the sample app:

| HMA state | app sees | `ROOT_MANAGER_PACKAGE` | Execution coverage |
| --- | --- | --- | --- |
| not aimed at us | `ksunext` + `hma_oss` | **LIKELY**, `count=2` | 75% |
| aimed at us | nothing | **INCONCLUSIVE** + `META_VISIBILITY_RESTRICTED` | 62% |

The second row is the SDK behaving correctly under live attack — hard rules 2 and 9 verified
against a real adversary rather than a fixture. The first row is its positive control; without
it the second proves nothing.

Adding the cloaker to `<queries>` does not help: with `org.frknkrc44.hma_oss` explicitly
queried, a configured HMA still hid it. Nor is there an in-process trace to fall back on —
app maps were **797 distinct paths with hiding active and 797 without**, differing only in
thread-stack TIDs, because HMA-OSS filters in `system_server` and never enters our address
space. Same conclusion as ReZygisk above, reached by a different route.

**`run-as` is not a valid proxy for app-process package visibility.** A `run-as` shell saw
packages the app process could not: it is not zygote-forked and does not inherit the hooks.
Any visibility measurement taken through `run-as` and reported as an app result is wrong.
Measure from the app.

**The `ROOT_PROP_SPOOF` redesign has no positive control here either.** All seven
`ro.*.build.fingerprint` values (`build`, `system`, `vendor`, `product`, `odm`, `system_ext`,
`bootimage`) are byte-identical, and the composed fingerprint matches every component
(`ro.product.brand`/`name`/`device`, `ro.build.id`, `.version.incremental`, `.type`, `.tags`).
Nothing is spoofed on this device: root is kernel-side, so no property rewriting is needed.
An app-visible cross-check is still the right redesign — it just cannot be falsified until a
Magisk + Play Integrity Fork configuration exists to fail it.

### The hook family gets a positive control, measured 2026-09-01

`K2` = `K1` plus **Vector v2.2**, an Xposed framework resident in hooked processes. LSPosed
itself was unusable: last release October 2023, three Android versions behind this device's
API 36. `JingMatrix/Vector` is its maintained successor (Android 8.1–17). Installed via `ksud`
alongside the existing ReZygisk v1.0.0, which is current; no Zygisk replacement was needed and
the device did not bootloop.

**Vector does not inject into an app with no module scoped to it.** With the framework active
but nothing targeting `sample-app`, the process gained **zero** new mappings. That is the
design working, not a null result — and it means the control has to be armed deliberately, by
scoping a module. `HideMyApplist` cannot serve: it pins its scope to `system` in its own
`module.prop`, which independently confirms the 797/797 result above — HMA hooks
`system_server` and architecturally cannot leave an app-process trace.

With an in-process module scoped to `sample-app`:

| Probe | `K2` hooked | `K1` clean | `C1` clean | Outcome |
| --- | --- | --- | --- | --- |
| Executable, file-backed mapping outside allow-listed prefixes | **1** | 0 | 0 | `HOOK_UNEXPECTED_MODULE` — **control fires** |
| App's own `/proc/self/maps` vs root's view of the same pid | 3 = 3 | — | — | `HOOK_MAPS_INCONSISTENT` — no divergence |
| `XposedBridge` / `XposedHelpers` / `XposedInterface` resolve | no | no | — | `HOOK_XPOSED_CLASSES` — **blind** |
| Suspicious stack frames | 0 of 90 | 0 of 90 | — | `HOOK_XPOSED_STACK` — **blind** |

The single hit is `/data/adb/modules/zygisk_vector/zygisk/arm64-v8a.so`, mapped `r-xp`. The app
can read that path out of its own maps **while being denied `stat` on the file it is currently
executing** — which is why artefact probing by path is a duplicate of the mapping check rather
than an independent one.

**Two qualifiers carry the whole detector.** Matching every mapping leaves 113 unexplained
paths on `K1`; requiring **executable and file-backed** drops that to zero, because ART's heap
regions are anonymous and `frro`/`idmap` overlays are not executable. Neither class had to be
enumerated.

**The second device earned its keep.** The rule as first written produced **two false positives
on `C1`** — ART's compiled boot image under `/data/misc/apexdata/com.android.art/dalvik-cache/`
— which `K1` never exhibits. One allow-list entry fixes it. Validated on the Pixel alone, this
detector would have fired on every MIUI device. Compare the `vector` substring trap: it matches
ART's own `dalvik-Concurrent mark-compact chunk-info vector` on every Android device ever
shipped. Both are the same mistake, and only a second device catches either.

**What this cost and bought.** Two catalogued detectors (`HOOK_XPOSED_CLASSES`,
`HOOK_XPOSED_STACK`) were marked `BUILD` and are measurably blind; a third
(`HOOK_XPOSED_ARTEFACTS`) became a duplicate. One (`HOOK_UNEXPECTED_MODULE`) moved from `DEFER`
to `BUILD` with a control that fires. The net is one buildable detector and three cancelled —
which is the rule in `CONTRIBUTING.md` paying for itself by *removing* work, an outcome that is
easy to miss because nothing ships.

### Property spoofing, measured 2026-09-01 — and why there is still no control

`K3` = `K1` plus **Play Integrity Fork v18**, configured with a deliberately foreign fingerprint
(`google/husky/husky:14/…`, a Pixel 8 Pro) on a `stallion` Pixel 10a. Built, measured, and torn
down the same day; `K1` was verified restored afterwards.

**No Magisk was involved, and none was needed.** Magisk cannot coexist with KernelSU Next — it
requires flashing a different boot image, which would have destroyed `K1` and the `K2` rig built
hours earlier. PIF is a Zygisk module and installs on the existing ReZygisk. The guide that
prompted this experiment assumes Magisk because that is what *its* author ran, not because the
technique needs it.

**Half one: PIF does not spoof the properties.** Predicted from source — no script in the module
writes `ro.*.build.fingerprint` — and confirmed on device. With PIF active and `husky`
configured, all seven partition properties still read `stallion`.

**Half two: PIF does not spoof our process either.** The app's own `android.os.Build.FINGERPRINT`
read `stallion`, not `husky`. `killpi.sh` names the targets: `com.google.android.gms.unstable`
and `com.android.vending`.

That generalises, and it is the finding worth keeping: **spoofing aimed at attestation targets
the attestation client, not the device.** Rewriting properties device-wide breaks unrelated
software and fools nobody extra, since only Google's process needs deceiving. A third-party app
therefore cannot observe this class of spoofing at all — not because it is well hidden, but
because it was never applied to that app. `ROOT_PROP_SPOOF` has no positive control for a
structural reason, not for want of a rig.

**And the check as specified fires on a clean device.** The probe reported
`partitionsAgree=false` on a device where `getprop` showed all seven byte-identical:

```
ro=stallion | ro.system=stallion | ro.vendor=stallion | ro.product=stallion
| ro.odm=stallion | ro.bootimage=<EMPTY> | ro.system_ext=stallion
```

`ro.bootimage.build.fingerprint` is **unreadable to an app** — property reads are labelled by
SELinux context — and returns an empty string, which a naive comparison scores as a difference.
This is precisely the failure `DETECTION_TRIAGE.md` opens by warning about: a check that fires
on a clean device and stays silent on a rooted one. An implementation must treat empty as
unreadable-per-property and drop `ro.bootimage` from the comparison set.

**Method note, and a correction.** This was visible only because the probe ran *inside the app*.
Through `adb shell` — or `run-as` — every property agrees and the trap is invisible. The caveat
added to `DETECTION_TRIAGE.md` earlier the same day said filesystem **and property** results
transfer between shell and app; the property half of that was wrong and is now corrected there.
Only filesystem results transfer.

### Two kinds of coverage

`coverage` is **execution** coverage: the fraction of registered detectors that reached a
conclusion. It is not threat coverage and must never be read as one.

| | Pixel |
| --- | --- |
| Execution coverage | 100% |
| `ROOT_*` techniques catalogued | 14 |
| `ROOT_*` producing a positive on a rooted device | **1** |

That one is defeated by renaming an application. Report both numbers or neither.

### Automating this, and the half that cannot be

The two halves are not equally achievable, and pretending otherwise is how a baseline rots:

- **The clean control is already in CI** as the `Clean-device negative control` job — a
  release-keys emulator asserting no root signals fire. That is the half that runs per-commit.
- **The positive control cannot be.** No hosted runner has a rooted Pixel, and no emulator
  substitutes for one (`PLAN.md` §Phase 2). It needs either a self-hosted runner with the
  device attached, or this section re-measured at release checkpoints with the device, build
  fingerprint and date recorded above.

Until one of those exists, §2's own warning applies to this section: these numbers are
**tribal knowledge on one engineer's spare phone**, written down. Treat a figure here with no
recent date as unverified rather than true.

### Why this section is a liability if left alone

Four times during the work that produced it, a check that had stopped running still reported
success: an instrumented positive control that could print `SKIPPED` and pass, a mutation
pattern silently degraded to a skip, `META_VISIBILITY_RESTRICTED` documented in four places and
implemented in none, and `README.md` claiming no detectors existed long after seven shipped.

A static table is the same shape of hazard. The coverage figures above are assertable — the
clean control could pin its own — and anything here that cannot be asserted should carry the
date it was last confirmed by hand.
