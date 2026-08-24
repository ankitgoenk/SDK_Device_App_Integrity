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
| **KernelSU / APatch** | Custom kernel | `ROOT_KERNELSU` / `ROOT_APATCH` |
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
4. Patch the scoring layer to always produce `TRUSTED`.
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
