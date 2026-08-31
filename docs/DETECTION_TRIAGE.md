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

## Outcomes

| Outcome | Meaning |
| --- | --- |
| **BUILT** | Implemented and measured on the reference devices |
| **BUILD** | Observable, a positive control exists or is constructible, worth the false-positive cost |
| **DEFER** | Observable, but no positive control yet — *do not implement until one exists* |
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

**4. Triage by mechanism, not by row.** Six catalogue entries hinge on package visibility and
share one answer. Working the list linearly rediscovers the same fact six times.

## Reference stacks

| Ref | Device | State |
| --- | --- | --- |
| `K1` | Pixel 10a, Android 16 | KernelSU Next, susfs4ksu, ReZygisk, hma_oss_zygisk, tricky_store |
| `C1` | Xiaomi M2101K6I, Android 13 | Stock MIUI, unmodified |

Measurements below are from an **app context** (`u:r:runas_app`), not adb shell — shell is more
privileged and its results do not transfer. Recorded **2026-08-31**.

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
| `ROOT_PROP_SPOOF` | **DOCUMENT** (redesign pending) | Every named ground-truth source is privileged: `/system/build.prop` is `0600 root`, `/proc/bootconfig` is denied **even to shell**. `/proc/cmdline` is app-readable but carries no vbmeta entries on Android 12+. The spoofing on `K1` is real and unreachable: bootconfig says `vbmeta.device_state="unlocked"` and `verifiedbooterror="ERROR_VERIFICATION"` while the property reports `locked`. A redesign must compare app-visible values **against each other** | K1 |
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
| `HOOK_MAPS_INCONSISTENT` | **DOCUMENT** (not `DEFER`) | Proposed as loader-state vs `/proc/self/maps` divergence. **No divergence exists on `K1`**: root's view and the app's own view of the same process are byte-identical, and ReZygisk *unloads* from the forked child rather than hiding it — 6 zygisk mappings in `zygote64`, 0 in the app, in both views. There is nothing to observe, so there is no control to construct. Revisit only if a framework appears that scrubs maps rather than cleaning up after itself. **Compare address ranges, never path strings** — an APK-loaded `.so` maps under `…/base.apk`, so a name comparison fires on every device | K1 |
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

## Standing count

| | ROOT | Package-visibility | HOOK | ENV | Total |
| --- | --- | --- | --- | --- | --- |
| BUILT | 3 | (1 of the 6) | 1 | — | 5 |
| BUILD | 2 | 5 | — | 6 | 13 |
| DEFER | 2 | — | — | 1 | 3 |
| DOCUMENT | 6 | — | 1 | 2 | 9 |
| DUPLICATE | — | — | 1 | — | 1 |
| DECLINE | 1 | — | — | 1 | 2 |

**33 of 82 candidates triaged.** `EMU`, `VIRT`, `APP` and the remaining `HOOK` entries are
untouched. `EMU`/`VIRT` will need a third reference stack — neither reference device is an
emulator or a cloned container.
