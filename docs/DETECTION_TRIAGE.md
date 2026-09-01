# Detection Triage

[DETECTION_CATALOG.md](DETECTION_CATALOG.md) lists 82 candidate techniques. It is a catalogue of
what is *conceivable*, and it has been read as a backlog — a list of things someone ought to get
around to building. That reading is wrong, and expensive: several entries describe checks an
ordinary Android app is not permitted to make, and at least one, as specified, would fire on a
clean device and stay silent on a rooted one.

This file records the decision for each candidate, with the evidence behind it. Its eventual
value is not "we implemented N detectors". It is:

> we evaluated every candidate technique, and can show which are observable, which are worth
> building, and **why the rest are not** — so the same idea is not re-proposed every quarter.

**Status: 73 of 82 triaged.** The nine outstanding are `EMU` and `VIRT`, which cannot be settled
on the current hardware and are marked as such rather than guessed.

## Outcomes

| Outcome | Meaning |
| --- | --- |
| **BUILT** | Implemented and measured on the reference devices |
| **BUILD** | Observable, a positive control exists or is constructible, worth the false-positive cost |
| **DEFER** | Observable, but no positive control yet — *do not implement until one exists*. **Must name the configuration that would produce the control**, so the entry is a procurement item rather than an indefinite hold |
| **DOCUMENT** | Not observable by an unprivileged app, or the technique as specified cannot work. The id stays; ids are deprecated, never reused |
| **DUPLICATE** | Covered by another detector, or shares its bypass so completely that it adds no independent evidence |
| **DECLINE** | Observable and buildable, rejected on false-positive or user-harm grounds |

## Rules

**1. Observability first.** Ask *"can an unprivileged app see this?"* before anything else. It
eliminates candidates in minutes that would otherwise consume days. Six `ROOT_*` entries died
at this question.

**2. No detector without a positive control that has been seen to fail.** A control that has
never gone red is a comment. During the work that produced this file, four checks that had
stopped running still reported success — see [TESTING.md §9](TESTING.md#9-measured-baseline--the-two-reference-devices).

**3. Every verdict names the stack it was tested against.** We have exactly one rooted
configuration. "Not observable on KernelSU Next + susfs" is not "not observable". `ROOT_SU_BINARY`
is blind here because KernelSU scopes `su` to granted namespaces; on Magisk with DenyList off,
the same detector fires.

**4. The control must match the attacker, not the device on hand.** `K1` is the right control
for `ROOT_*` and `HOOK_*`. It is the *wrong* control for `APP_TAMPER`: `APP_DEX_DIGEST_MISMATCH`
targets a mass-distributed repackaged app on an ordinary unrooted phone, where the client is
honest and the server-side comparison is decisive, so its positive control is a synthetic
tampered archive in a unit test and no configuration of `K1` improves on that. Judging every
candidate against the rooted phone quietly biases the SDK toward anti-root and away from the
family with the broader reach.

**5. Triage by mechanism, not by row.** Six catalogue entries hinge on package visibility and
share one answer. Working the list linearly rediscovers the same fact six times.

## Reference stacks

| Ref | Device | State |
| --- | --- | --- |
| `K1` | Pixel 10a, Android 16 | KernelSU Next, susfs4ksu, ReZygisk, hma_oss_zygisk, tricky_store |
| `C1` | Xiaomi M2101K6I, Android 13 | Stock MIUI, unmodified |
| `K2` | `K1` plus Vector v2.2 (3080) | Xposed framework, resident in hooked processes. Added 2026-09-01 as the hook-family positive control. **LSPosed itself was not usable** — last release Oct 2023, three Android versions behind `K1`'s API 36; `JingMatrix/Vector` is its maintained successor and supports 8.1–17 |
| `K4` | `K1` plus Vector and `tools/xposed-buildspoof-fixture` | The `ROOT_PROP_SPOOF` positive control, and it lives in this repository. A scoped Xposed module rewrites `android.os.Build` for `io.integrity.sample` only and deliberately leaves the backing properties alone. Rebuild with `:tools:xposed-buildspoof-fixture:assembleDebug`; its API stubs are `compileOnly` because a module that packages them is refused by the framework |
| `K3` | `K1` plus Play Integrity Fork v18, **built and torn down 2026-09-01** | Property/`Build` spoofer. Removed after measurement: it gave no positive control and left `K1` diverging from the baseline documented here. Rebuildable in minutes from this row — it needs no Magisk, contrary to the guide that suggested it |

Measurements below are from an **app context** (`u:r:runas_app`), not adb shell — shell is more
privileged and its results do not transfer. Recorded **2026-08-31**.

> **`run-as` is not the app process, and for anything hooked it gives the wrong answer.**
> A `run-as` shell is not zygote-forked, so it does not inherit Zygisk/LSPosed injection or
> per-uid package filtering applied to the app. Measured 2026-09-01: with Hide My AppList
> aimed at the sample app, `run-as` still listed `com.rifsxd.ksunext` and
> `org.frknkrc44.hma_oss` while the app process saw neither (TESTING.md §9).
>
> **Property reads do not transfer either — this note said they did, and that was wrong.**
> Corrected 2026-09-01: `ro.bootimage.build.fingerprint` returns its full value to `adb shell`
> and an **empty string** to the app, because the two run in different SELinux contexts and
> property reads are labelled per-context. Only *filesystem* results transfer. Package
> visibility, in-process state **and system properties** must all be re-measured from inside
> the app before being relied on.

---

## 1. ROOT

| SignalId | Outcome | Evidence | Stack |
| --- | --- | --- | --- |
| `ROOT_SU_BINARY` | **BUILT** | 15 paths probed from an app context. `/system/bin/su` is visible to shell and **`ENOENT` to the app** — KernelSU exposes `su` only in granted namespaces, so this is not hiding, it is how the grant works. Blind here; would fire on Magisk with DenyList off | K1, C1 |
| `ROOT_MANAGER_PACKAGE` | **BUILT** | The only positive any detector produced on a rooted device: `LIKELY`, after `com.rifsxd.ksunext` was added to the list **and** the `<queries>` fragment. Defeated by renaming the manager | K1, C1 |
| `ROOT_DANGEROUS_PROPS` | **BUILT** (reclassified) | Detects a modified *build*, not root. `K1` is genuinely `user`/`release-keys` — nothing spoofed, the check answers a different question than its name implies | K1, C1 |
| `ROOT_VERIFIED_BOOT` | **BUILD** (low value, stated) | `ro.boot.*` **is** app-readable. Both devices report `verifiedbootstate=green`, `flash.locked=1` — and on `K1` that is false (see `ROOT_PROP_SPOOF`). Catches careless setups only; reads clean on a hidden root. Ship `INFORMATIONAL` with the blind spot in the row | K1, C1 |
| `ROOT_UID_ZERO` | **BUILD** (invariant) | `/proc/self/status` is app-readable; both devices report a normal app uid. No positive control is constructible — an ordinary app cannot run as uid 0 — so this ships as a cheap invariant whose firing means something has gone very wrong, not as a root check | K1, C1 |
| `ROOT_RW_SYSTEM` | **DEFER** | `/proc/self/mounts` is app-readable and parseable. Zero `rw` mounts on `/system` or `/vendor` on both devices. Observable, but **no positive control** until a device with `/system` remounted read-write exists | K1, C1 |
| `ROOT_MOUNT_ANOMALY` | **DEFER** (naive form inverts) | Measured inversion: the **clean** `C1` shows **19** overlay mounts, the **rooted** `K1` shows **0**. `C1`'s are legitimate MIUI partition composition (`/product/overlay`, `/product/app`, `/product/lib`…). An overlay-counting detector would false-positive on the clean device and miss the rooted one. `/proc/1/mounts`, the namespace comparison that would make this meaningful, is **denied to the app** | K1, C1 |
| `ROOT_MAGISK_PATHS` | **DOCUMENT** | `/data/adb` is **denied** to the app on both devices. The catalogue already said the literal path form always answers "no" | K1, C1 |
| `ROOT_KERNELSU` | **DOCUMENT** (path form) | `/data/adb/ksu`, `/data/adb/ksud` denied. The *manager package* is detectable and already is — see `ROOT_MANAGER_PACKAGE`, which caught this exact stack | K1 |
| `ROOT_APATCH` | **DOCUMENT** (path form) | `/data/adb/ap` denied, same mechanism. Package form covered by `ROOT_MANAGER_PACKAGE`, to which `me.bmax.apatch` has been added | K1, C1 |
| `ROOT_SELINUX_PERMISSIVE` | **DOCUMENT** | `/sys/fs/selinux/enforce` is **denied** to the app on both devices. Readable from shell, which is why this looks implementable and is not | K1, C1 |
| `ROOT_INIT_ARTEFACTS` | **DOCUMENT** | `/data/adb/**`, `su.d`, `init.d` — all under paths denied to the app | K1, C1 |
| `ROOT_PROP_SPOOF` | **BUILT** (was `DOCUMENT`) | The partition cross-check is dead and the reasons are recorded in TESTING.md §9: PIF writes no `ro.*.build.fingerprint`, scopes its `Build` spoofing to GMS, and a partition comparison scores **26 disagreements on a clean Redmi against 3 on `K1`** because Treble lets partitions come from different vendors on different days. What shipped instead compares each `android.os.Build` field to the property that backs it — an invariant the framework maintains rather than a convention vendors follow. Positive control on **`K4`**: a scoped Xposed module rewrites `Build` and leaves the property, exactly as PIF does to GMS. Fires `CONFIRMED` scoped, silent unscoped, silent on `C1` | K1, C1, **K4** |
| `ROOT_SU_EXEC` | **DECLINE** | Observable and buildable. Rejected on user-harm grounds: spawning `su` may raise a root-grant prompt on the user's device, which is an SDK doing something visible and alarming on a host app's behalf. Already "disabled by default, opt-in only" in the catalogue; this makes it a decision rather than a default | — |

### What the ROOT branch actually says

Fourteen catalogued techniques. **Six are not observable by an unprivileged app at all** — every
one of them fails on a path that shell can read and an app cannot, which is exactly why they look
implementable from a terminal. Three are built. Two are deferred for want of a positive control,
one of which inverts in its obvious form. One is declined.

The single technique that fires on a rooted device is a package-name lookup, defeated by
renaming an application.

---

## 2. Package visibility — one mechanism, six entries

`ROOT_MANAGER_PACKAGE`, `ENV_PATCHER_APP`, `ENV_MEMORY_EDITOR`, `ENV_MITM_PROXY_APP`,
`ENV_CLONER_APP`, `ENV_HOOK_MANAGER_APP` all reduce to the same question, and it is answered:

- Observable **iff the package is declared** in `integrity-detector-environment`'s `<queries>`
  fragment. `QUERY_ALL_PACKAGES` is forbidden (ADR-0004).
- A hit is evidence. **A miss is not**, unless the package was declared — and even then, an
  app-list hider (`hma_oss_zygisk` is live on `K1`) can suppress it.
- `RealPackageProbe.absenceIsConclusive` is `SDK_INT < R || hasQueryAllPackages()`, so it is
  permanently false on modern Android. Since `<queries>` now declares the managers explicitly and
  the platform guarantees their visibility, absence of a *declared* package **is** conclusive.
  Narrowing this is a change to what absence means, and needs an ADR note.

**Consequence for the remaining five:** they are `BUILD`, they inherit a curated-list maintenance
burden, and each is only as current as its list. `ROOT_MANAGER_PACKAGE` was stale enough to miss
the manager on the project's own reference device.

---

## 3. HOOK — entries already settled

| SignalId | Outcome | Evidence | Stack |
| --- | --- | --- | --- |
| `HOOK_SELF_TEXT_MISMATCH` | **BUILT** | Ran clean on both devices. Blind to GOT/PLT redirection and ART entry-point swaps, which change no executable byte | K1, C1 |
| `HOOK_MAPS_INCONSISTENT` | **DOCUMENT** (not `DEFER`) | Proposed as loader-state vs `/proc/self/maps` divergence. **No divergence exists on `K1`**: root's view and the app's own view of the same process are byte-identical, and ReZygisk *unloads* from the forked child rather than hiding it — 6 zygisk mappings in `zygote64`, 0 in the app, in both views. There is nothing to observe, so there is no control to construct. Revisit only if a framework appears that scrubs maps rather than cleaning up after itself. **Re-tested on `K2` and the verdict holds for a stronger reason**: Vector stays *resident* in the hooked process and still does not hide — the app's own `/proc/self/maps` and root's view of it both show the same 3 mappings. A framework that never unloads is the best case for this check, and there is still no divergence. **Compare address ranges, never path strings** — an APK-loaded `.so` maps under `…/base.apk`, so a name comparison fires on every device, and `vector` as a substring matches ART's own `dalvik-Concurrent mark-compact chunk-info vector` on every device ever shipped | K1, **K2** |
| `HOOK_PLT_GOT` | **DUPLICATE** (partial) | Its own catalogue row: hooking the reading path defeats it and `HOOK_SELF_TEXT_MISMATCH` identically, so *"the two are not independent"*. It adds coverage only against attackers who redirect GOT without hooking reads. Build it for that case knowingly, or not at all | — |

---

## 4. ATTESTATION FORGERY — a category the catalogue lacks

The catalogue's `ATT_*` family is *consuming* an attestation verdict. It has no entry for the
verdict being **forged**, and that is live on the reference device.

`K1` runs **`tricky_store` with 354 target packages**, including `android`,
`com.android.vending`, `com.google.android.gms` and `io.github.vvb2060.keyattestation` — the
key-attestation checker app. Its purpose is to forge Keystore key-attestation certificates.

**Outcome: DOCUMENT, and it is already load-bearing.**
[ADR-0011](adr/0011-report-signing-without-attestation.md) declined to depend on Keystore key
attestation on principle — ADR-0008 puts attestation out of scope, hard rule 9 forbids
trust-raising inputs. This device shows the scheme would also have been *defeated in practice*.
Not a detector; evidence for a decision already taken.

---

---

## 5. ENV

Measured with a temporary in-app probe using the real app APIs, then removed. `adb shell` cannot
answer these: most are `Settings` and framework calls whose permission checks differ entirely
from a file read, and shell is more privileged besides.

| SignalId | Outcome | Evidence | Stack |
| --- | --- | --- | --- |
| `ENV_ADB_ENABLED` | **BUILD** | `Settings.Global.ADB_ENABLED` and `DEVELOPMENT_SETTINGS_ENABLED` read without permission; both return `1` on both devices. Note both are developer devices — this discriminates nothing here, and its false-positive population is *every developer* | K1, C1 |
| `ENV_ADB_OVER_NETWORK` | **BUILD** | `android.os.SystemProperties.get` **is reachable by reflection** on API 33 and API 36 — returned empty (property unset), not denied. Control constructible by enabling wireless debugging | K1, C1 |
| `ENV_USER_CA_INSTALLED` | **BUILD** | `KeyStore("AndroidCAStore")` enumerates: 143 aliases on `K1`, 129 on `C1`, `user:` count **0** on both. Correct negative; control constructible by installing a user CA | K1, C1 |
| `ENV_PROXY_CONFIGURED` | **BUILD** | `System.getProperty("http.proxyHost")` readable, `none` on both | K1, C1 |
| `ENV_ACCESSIBILITY_SERVICE` | **BUILD** | `Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES` read succeeded (null — none enabled on either device). Control constructible by enabling TalkBack | K1, C1 |
| `ENV_FRIDA_SERVER_DROP` | **BUILD** (technique redefined) | **As specified it cannot work**: `/data/local/tmp` exists but `listFiles()` returns null, so pattern-matching an enumeration is impossible. A *fixed-name* probe does work, proven with a real positive control — an empty `frida-server` was planted as root, `File(...).exists()` returned it, and it was removed. The detector must probe a curated name list, and inherits that list's staleness | K1 |
| `ENV_SCREEN_CAPTURE_ACTIVE` | **BUILD** (API 34+) | `Activity.registerScreenCaptureCallback` present on `K1` (API 36), **absent** on `C1` (API 33). Below 34 there is no supported detection; the signal must report `INCONCLUSIVE` rather than absent | K1, C1 |
| `ENV_VPN_ACTIVE` | **DEFER** (permission cost) | `NetworkInterface.getNetworkInterfaces()` returns **null** to an app with no permission — the enumeration route does not work. `ConnectivityManager`/`TRANSPORT_VPN` needs `ACCESS_NETWORK_STATE`, which the SDK would impose on every host. Defer until that trade is a decision someone takes deliberately | K1, C1 |
| `ENV_UNKNOWN_SOURCES` | **DECLINE** (permission cost) | `canRequestPackageInstalls()` throws `SecurityException` unless the caller declares `REQUEST_INSTALL_PACKAGES` — a **Play-restricted permission**. An integrity SDK demanding it is the same non-starter as `QUERY_ALL_PACKAGES` (ADR-0004), and for the same reason | K1, C1 |
| `ENV_OVERLAY_DETECTED` | **DOCUMENT** (host integration, not a detector) | `MotionEvent.FLAG_WINDOW_IS_OBSCURED` is delivered to *the host's own views* during touch. The SDK has no window and receives no events, so this cannot be a passive detector. It is guidance for the host — set `filterTouchesWhenObscured` on sensitive views — and at most an API for the host to report into | — |
| `ENV_PLAY_PROTECT_OFF` | **DOCUMENT** (`SRV`) | The catalogue sources it from Play Integrity `environmentDetails.playProtectVerdict`. Server-side vocabulary like `ATT_*`; nothing here emits it, and the local `package_verifier_enable` key read back null on both devices | K1, C1 |
| `ENV_PATCHER_APP`, `ENV_MEMORY_EDITOR`, `ENV_MITM_PROXY_APP`, `ENV_CLONER_APP`, `ENV_HOOK_MANAGER_APP` | **BUILD** | Package visibility — see §2. One mechanism, one answer, five entries | K1, C1 |

### What the ENV branch says

Sixteen entries. Eight are straightforwardly buildable and cheap — a better hit-rate than ROOT,
because these are *environment* facts the platform is willing to tell an app about rather than
privileged state it actively hides.

Two findings generalise beyond ENV.

**`android.os.SystemProperties` is reachable by reflection** on both API 33 and API 36. That is
the mechanism `ROOT_VERIFIED_BOOT` needs, and it confirms property reads are app-observable in
general — while remaining trivially spoofable, as `K1` demonstrates.

**Permission cost is a triage axis the outcomes above did not have.** Two ENV candidates are
perfectly observable and still fail, because reaching them means the SDK forcing a permission
onto every host: `ACCESS_NETWORK_STATE` for VPN, and `REQUEST_INSTALL_PACKAGES` — Play-restricted
— for unknown sources. ADR-0004 already made this judgement once, for `QUERY_ALL_PACKAGES`. A
signal an SDK cannot obtain without making its integrator's app more privileged is not free, and
the cost lands on someone who never asked for the signal.

---

## 6. APP

Measured with a temporary in-app probe, then removed. These are mostly *self*-introspection, so
the platform is generally willing — the interesting failures are elsewhere.

| SignalId | Outcome | Evidence | Stack |
| --- | --- | --- | --- |
| `APP_SIGNATURE_MISMATCH` | **BUILT** | Ran and matched on both devices once a pin was configured. Without a pin it reports `no_pin_configured`, which was its state in every run before the baseline | K1, C1 |
| `APP_NATIVE_LIB_MISMATCH` | **BUILT** | Build-token comparison in the native core; silent on both | K1, C1 |
| `APP_PACKAGE_MISMATCH` | **BUILD** | `context.packageName` against the configured expectation. `IntegrityConfig.expectedPackageName` already exists and nothing reads it | K1, C1 |
| `APP_INSTALLER_UNEXPECTED` | **BUILD** | `getInstallSourceInfo()` succeeds and returns `installingPackageName=null` on both — the adb-install case. **Both reference devices are already the positive control**: a sideloaded app is exactly what a null installer means | K1, C1 |
| `APP_DEBUGGABLE_FLAG` | **BUILD** | `FLAG_DEBUGGABLE=true` on both, correctly, because `sample-app` is a debug build. Trivially observable; the control is a build variant | K1, C1 |
| `APP_UNEXPECTED_DEX` | **BUILD** | Hidden-API reflection into `dalvik.system.BaseDexClassLoader.pathList` **still works** on API 33 and 36 — `dexElements=1` on both. That was the open question | K1, C1 |
| `APP_PROCESS_NAME_ANOMALY` | **BUILD** | `/proc/self/cmdline` readable; matches the package on both | K1, C1 |
| `APP_DEX_DIGEST_MISMATCH` | **BUILD** (blocked) | Own APK readable (10.2 MB). Observable, but needs the build-time baseline from `integrity-baseline-plugin`, which is phase 4 and unbuilt. The dependency is a plugin, not a platform limit | K1, C1 |
| `APP_RESOURCE_TAMPER` | **BUILD** (blocked) | Same shape and the same baseline dependency | — |
| `APP_TASK_HIJACK_RISK` | **DOCUMENT** (host posture, not a detector) | `taskAffinity` reads back fine — but it describes **the host's own manifest**, not the device. It cannot distinguish a compromised device from a badly configured app, and the fix is the host's to make. This is lint for integrators, like `ENV_OVERLAY_DETECTED` | K1, C1 |

Seven of ten are buildable and two of those wait only on a plugin. APP is the healthiest branch
in the catalogue — unsurprising, since asking a process about itself is the one thing Android
does not restrict.

---

## 7. HOOK

Two entries were already settled (`HOOK_SELF_TEXT_MISMATCH` BUILT, `HOOK_PLT_GOT` DUPLICATE —
see §3). The remaining eighteen:

| SignalId | Outcome | Evidence | Stack |
| --- | --- | --- | --- |
| `HOOK_FRIDA_MAPS` | **BUILD** | `/proc/self/maps` readable; 715 distinct paths on `K1`, 551 on `C1` | K1, C1 |
| `HOOK_FRIDA_THREADS` | **BUILD** | `/proc/self/task` is listable and every `comm` readable — 13 threads on `K1`, 16 on `C1` | K1, C1 |
| `HOOK_FRIDA_ARTEFACTS` | **BUILD** | Fixed-name probes into `/data/local/tmp` work; proven with a planted decoy (§5) | K1 |
| `HOOK_FRIDA_MEMSCAN` | **BUILD** (native, costly) | Reading own executable regions is proven by `HOOK_SELF_TEXT_MISMATCH`. Scanning them for fingerprints is the same primitive at much greater cost | K1, C1 |
| `HOOK_XPOSED_CLASSES` | **DOCUMENT** (was `BUILD`; measured blind on `K2`) | `Class.forName` works, but there is nothing for it to find. With Vector active **and a module hooking the process**, none of `de.robv.android.xposed.XposedBridge`, `XposedHelpers` or `io.github.libxposed.api.XposedInterface` resolves — hooked and clean readings are identical. A modern framework injects its API into the **module's** classloader, not the target app's. This was `BUILD` on the reasoning that a hit is evidence; the measurement says there is no hit to have | K1, C1, **K2** |
| `HOOK_XPOSED_STACK` | **DOCUMENT** (was `BUILD`; measured blind on `K2`) | Stack-trace inspection works. Under an active hook it returns **90 frames with 0 suspicious, byte-identical to the clean reading** — LSPlant-style hooking rewrites the ART method entry point and leaves no frame of its own. The legacy technique assumed a Java-level bridge frame that modern frameworks do not produce | K1, C1, **K2** |
| `HOOK_XPOSED_ARTEFACTS` | **DUPLICATE** of `HOOK_UNEXPECTED_MODULE` (was `BUILD` partial) | `/system/framework/**` probes return nothing; every `/data/adb` path is denied, confirmed again on `K2` — the app cannot `stat` the framework `.so` it is currently executing. But it can **read the path out of its own `/proc/self/maps`**, which is how the same evidence arrives by a route that works. Stat-based artefact probing adds nothing the mapping check does not already give | K1, C1, **K2** |
| `HOOK_ART_METHOD_ANOMALY` | **BUILD** | `Modifier.isNative` on sampled framework methods reads correctly (`false` for both probes on both devices). A Java-level hook typically flips this | K1, C1 |
| `HOOK_INLINE_PROLOGUE` | **BUILD** (native) | Same primitive as the shipped self-text measurement, pointed at `libc`/`libart` symbols instead of our own `.text` | — |
| `HOOK_DEBUGGER_ATTACHED` | **BUILD** | `Debug.isDebuggerConnected()` — `false` on both | K1, C1 |
| `HOOK_TRACER_PID` | **BUILD** | `/proc/self/status` readable, `TracerPid: 0` on both. Control is constructible by attaching a debugger | K1, C1 |
| `HOOK_JDWP_ENABLED` | **BUILD** | Reduces to the debuggable flag, already measured | K1, C1 |
| `HOOK_LDPRELOAD` | **BUILD** | `/proc/self/environ` readable on both; no `LD_PRELOAD`/`LD_LIBRARY_PATH` present | K1, C1 |
| `HOOK_UNEXPECTED_MODULE` | **BUILD** (was `DEFER`; the allow-list is solved and the control fires) | The 113/28 unexplained paths came from matching *every* mapping. Restricting to **executable (`r-x`), file-backed** mappings collapses them to **0 on `K1` and 0 on `C1`**: ART heap regions are anonymous and `frro`/`idmap` overlays are not executable, so both classes disappear without being enumerated. Measured rule — executable, file-backed, outside `/system`, `/apex`, `/vendor`, `/product`, `/system_ext`, `/data/app` and `/data/misc/apexdata/com.android.art/`. Scores **0 clean / 1 hooked / 0 on `C1`**, the one being `/data/adb/modules/zygisk_vector/zygisk/arm64-v8a.so`. The final allow-list entry is not cosmetic: ART's compiled boot image appears there on `C1` and **never on `K1`**, so a rule validated on the Pixel alone would fire on every MIUI device | K1, C1, **K2** |
| `HOOK_PTRACE_SELF` | **DOCUMENT** (mitigation, not a detector) | Forking a watchdog to occupy the ptrace slot *prevents* attachment. It emits no evidence and belongs in `ANTI_TAMPER.md`, not a signal catalogue | — |
| `HOOK_FRIDA_PORT` | **DECLINE** | Connecting to `127.0.0.1:27042` throws `SocketException` without `INTERNET`. Beyond the permission, it needs an explicit ADR: **ADR-0003 says the SDK performs no network IO**, and whether a loopback probe counts is a question no one has answered. Hard rule 1 permits socket IO off the main thread, so this is genuinely undecided — and must be decided before it is built, not after | K1, C1 |
| `HOOK_FRIDA_PORTSCAN` | **DECLINE** | Everything above, multiplied by a bounded port sweep of the user's own device | — |
| `HOOK_SUBSTRATE` | **DECLINE** (obsolete) | Cydia Substrate has been unmaintained for years and is absent from every modern hooking stack, including the one on `K1`. Maintaining a probe for it is upkeep with no expected yield | — |

Thirteen of eighteen are buildable, which makes HOOK look healthy — but note *what* is
buildable. The cheap wins are debugger and environment checks that any competent attacker
disables first. The techniques with real teeth against `K1`'s stack are the native ones, and
they share `HOOK_SELF_TEXT_MISMATCH`'s bypass: hook the reading path and every one of them sees
the original bytes.

---

## 8. ATT — vocabulary, not detectors

All six are **DOCUMENT**, and the reason is settled rather than measured:
[ADR-0008](adr/0008-attestation-out-of-scope.md) put attestation outside this project. Nothing
here emits an `ATT_*` signal and nothing should. They are the identifiers an *integrator* uses to
feed their own Play Integrity verdicts into `RiskScorer`.

| SignalId | Outcome | Notes |
| --- | --- | --- |
| `ATT_APP_NOT_RECOGNISED` | **DOCUMENT** | The only one that exists as a `SignalId` constant, and the only one in `RiskScorer.DECISIVE_SIGNALS`, where a `CONFIRMED` instance escalates to `COMPROMISED` |
| `ATT_DEVICE_INTEGRITY_FAIL` | **DOCUMENT** | Catalogue-only; no constant |
| `ATT_BASIC_INTEGRITY_FAIL` | **DOCUMENT** | Catalogue-only; no constant |
| `ATT_VIRTUAL_ONLY` | **DOCUMENT** | Catalogue-only; no constant |
| `ATT_APP_ACCESS_RISK` | **DOCUMENT** | Catalogue-only; no constant |
| `ATT_UNEVALUATED` | **DOCUMENT** | Catalogue-only; no constant |

### The missing constants are not the gap

`SignalId` is `public value class SignalId(public val value: String)` and
`Policy.withWeight(id, weight)` accepts any id, so an integrator can already write
`SignalId("ATT_DEVICE_INTEGRITY_FAIL")` and weight it. The vocabulary works today. Adding
constants would be convenience, and would also drag five ids into the catalogue gate for signals
this project never emits.

**The actual gap is that the integration path is untested.** `RiskScorerTest` exercises exactly
one id — `ATT_APP_NOT_RECOGNISED` — and no test drives an integrator-supplied attestation verdict
end to end. An integrator following the documentation gets a signal weighted `INFORMATIONAL`
unless they also call `withWeight`, and nothing in the suite would notice if that path broke.
One test, not five constants.

### The caveat that matters more than any of the above

**On a device running attestation forgery, an `ATT_*` input is not more trustworthy than our own
signals.** `K1` runs `tricky_store` with 354 targets including `com.android.vending`,
`com.google.android.gms` and the key-attestation checker app (§4).

Direction is what keeps this safe. Used to **incriminate** — the way `ATT_APP_NOT_RECOGNISED`
escalates — a forged verdict costs the attacker nothing they wanted and gains them nothing.
Used to **exonerate**, it is precisely what `tricky_store` exists to produce. ADR-0007 already
forbids the second, and this device is why that rule is not theoretical.

---

## 9. META — the SDK reporting on itself

All seven are **BUILT**, and each is emitted and tested. Verified rather than assumed, because
this family had a documented-but-absent member until recently:

| SignalId | Emitted by | Tests |
| --- | --- | --- |
| `META_DETECTOR_TIMEOUT` | `DetectionEngine` | 2 |
| `META_DETECTOR_ERROR` | `DetectionEngine` | 1 |
| `META_NATIVE_UNAVAILABLE` | `NativeIntegrityDetector`, escalated in `RiskScorer` | 4 |
| `META_NATIVE_NOT_CONFIGURED` | `NativeIntegrityDetector` | 1 |
| `META_NATIVE_FAILED` | `NativeIntegrityDetector` | 2 |
| `META_CONFIG_INVALID` | `IntegrityGuard` | 1 |
| `META_VISIBILITY_RESTRICTED` | `RootManagerPackageDetector` | 1 |

`META_VISIBILITY_RESTRICTED` is the cautionary one: ADR-0004, `INTEGRATION.md`, the catalogue and
the `<queries>` manifest comment all stated the report carried it, while the id did not exist and
nothing emitted it. It was implemented only after someone checked. The table above is that check,
run against the other six.

None of the seven fired on either reference device — no detector timed out, threw, or failed —
except `META_VISIBILITY_RESTRICTED`, which fires on `C1` and on every API 30+ device without a
root manager installed. That breadth is a known consequence of `absenceIsConclusive`, recorded in
the catalogue row.

## Standing count

Per family, so each column sums to the family's catalogue size and a miscount is visible.

| | ROOT (14) | ENV (16) | HOOK (20) | APP (10) | ATT (6) | META (7) | Total (73) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| BUILT | 4 | — | 1 | 2 | — | 7 | **14** |
| BUILD | 2 | 12 | 11 | 7 | — | — | **32** |
| DEFER | 2 | 1 | — | — | — | — | **3** |
| DOCUMENT | 5 | 2 | 3 | 1 | 6 | — | **17** |
| DUPLICATE | — | — | 2 | — | — | — | **2** |
| DECLINE | 1 | 1 | 3 | — | — | — | **5** |

**73 of 82 candidates triaged. The census is closed except for `EMU` (5) and `VIRT` (4).**

Those nine **cannot be triaged on the current hardware** — neither reference device is an
emulator or a cloned container, so every verdict would be an assumption, which is the failure
this document exists to prevent. They need a third stack: an AVD is free, and a Parallel
Space-style clone of `sample-app` is nearly free.

### What the closed census says

Of 73 candidates, **13 are built** and **34 more are buildable**. But the 34 is a backlog, not
capability, and the distribution is the point:

- **ROOT is exhausted at 3.** Six of its fourteen are not observable by an app at all, and no
  remaining candidate would add a second detection on `K1` — `ROOT_VERIFIED_BOOT` reads `green`
  there, `ROOT_MOUNT_ANOMALY` inverts, the rest are clean readings.
- **HOOK's 13 flatters it.** The cheap ones are debugger and environment checks an attacker
  disables first; the four with teeth share one bypass — hook the reading path and every one of
  them measures the original bytes.
- **APP is where the unblocked value is**, and two of its seven wait on
  `integrity-baseline-plugin` rather than on any platform limit. That plugin unblocks
  `APP_DEX_DIGEST_MISMATCH` and `APP_RESOURCE_TAMPER` together, and gives the SDK the one thing
  it currently cannot do: notice that *the app itself* changed — which, unlike everything in
  ROOT, a rooted device does not automatically defeat.

### Blocked on hardware, not on effort — the procurement list

Added 2026-09-01. Rule 3 warns that "not observable on KernelSU Next + susfs" is not "not
observable"; this is that warning made actionable. Each entry names the configuration that
would give it a control, so it reads as something to acquire rather than something to wait for.

| Candidate(s) | Blocked because | Configuration that unblocks it |
| --- | --- | --- |
| ~~`HOOK_XPOSED_CLASSES`, `HOOK_XPOSED_STACK`, `HOOK_XPOSED_ARTEFACTS`~~ | **Resolved 2026-09-01.** `K2` was built and all three were measured **blind under an active hook** — reclassified `DOCUMENT`, `DOCUMENT`, `DUPLICATE`. Two detectors cancelled before being written | — |
| ~~`HOOK_UNEXPECTED_MODULE`~~ | **Resolved 2026-09-01.** `K2` gave it the hook family's first working positive control, and the allow-list problem that caused its `DEFER` turned out to be solved by one predicate. Now `BUILD` | — |
| ~~`HOOK_MAPS_INCONSISTENT`~~ | **Resolved 2026-09-01, verdict unchanged.** `K2` answered it: Vector stays resident and still does not hide, so the app's view equals root's exactly. Stays `DOCUMENT`, now on evidence from a framework that had every opportunity to diverge | — |
| ~~`ROOT_PROP_SPOOF` (redesigned as app-visible cross-check)~~ | **Resolved 2026-09-01 — twice. First the answer was no; then a different comparison shipped with a control of its own (`K4`).** `K3` was built — **without Magisk**, which cannot coexist with KernelSU Next and would have destroyed `K1` and `K2`; PIF is a Zygisk module and installs on the existing ReZygisk. With PIF active and a deliberately foreign fingerprint configured, all seven partition properties were unchanged and the app's own `Build.FINGERPRINT` was unspoofed. No control exists because there is nothing to observe from a third-party process | — |
| `EMU_*`, `VIRT_*` (9 untriaged) | Neither reference device is an emulator or a clone | An AVD, and a Parallel Space-style clone of `sample-app`. Both nearly free; see above |

`K2` and `K3` are the same shape of work as `K1` and would settle six candidates between them.
That makes building them higher-leverage than any individual detector on the BUILD list — which
is the practical consequence of rule 2, stated as a plan rather than as a prohibition.

**What this list is not.** A configuration that produces a control does not make the detector
worth shipping; it makes it *assessable*. `ROOT_PROP_SPOOF` may still be declined on its bypass
ceiling once `K3` exists. Acquiring the hardware buys the right to decide on evidence.
