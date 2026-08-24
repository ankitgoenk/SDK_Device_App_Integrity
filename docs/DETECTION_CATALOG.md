# Detection Catalog

Every signal the SDK can emit. Each entry has a **stable `SignalId`** — IDs are contract,
never renamed. CI enforces that every `SignalId` in code has an entry here.

**Columns**
- **Weight** — default contribution to the category subscore (see [RISK_SCORING.md](RISK_SCORING.md)). `H`=high (25), `M`=medium (12), `L`=low (5), `I`=informational (0).
- **FP** — false-positive risk: `low` / `med` / `high`.
- **Layer** — `JVM`, `NAT` (native), `SRV` (server-verified).

---

## 1. Root & privileged environment

| SignalId | Technique | Layer | Weight | FP | Notes / known bypass |
| --- | --- | --- | --- | --- | --- |
| `ROOT_SU_BINARY` | Stat `su`, `busybox`, `magisk`, `supolicy`, `daemonsu` across `PATH` + `/sbin`, `/system/xbin`, `/system/bin`, `/vendor/bin`, `/data/local/{tmp,bin}`, `/su/bin` | NAT | H | low | Magisk DenyList hides paths from the app's mount namespace; renamed binaries |
| `ROOT_MAGISK_PATHS` | `/data/adb/magisk`, `/data/adb/modules`, `/sbin/.magisk`, `/cache/.disable_magisk`, `.overlay.d` | NAT | H | low | Hidden under DenyList; use with mount-anomaly signal |
| `ROOT_KERNELSU` | `/data/adb/ksu`, `/data/adb/ksud`, KernelSU manager `prctl` probe, kernel-version string anomalies | NAT | H | low | KernelSU deliberately leaves fewer userspace traces than Magisk |
| `ROOT_APATCH` | `/data/adb/ap`, APatch manager artefacts, kpatch markers | NAT | H | low | Newer; keep list updated |
| `ROOT_MANAGER_PACKAGE` | Presence of known root-manager packages (`com.topjohnwu.magisk`, `me.weishu.kernelsu`, `eu.chainfire.supersu`, `com.koushikdutta.superuser`, …) | JVM | M | low | Magisk supports repackaging the manager under a random package name — treat absence as no evidence |
| `ROOT_DANGEROUS_PROPS` | `ro.debuggable=1`, `ro.secure=0`, `ro.build.type=userdebug/eng`, `ro.build.tags` contains `test-keys`, `service.adb.root=1` | NAT | M | med | Some OEM/China ROMs and TV boxes legitimately ship `test-keys` |
| `ROOT_PROP_SPOOF` | Compare `__system_property_get` against `/system/build.prop` + `getprop` output; divergence indicates `resetprop` | NAT | H | low | Strong signal against property spoofing; needs careful parsing |
| `ROOT_VERIFIED_BOOT` | `ro.boot.verifiedbootstate != green`, `ro.boot.flash.locked != 1`, `ro.boot.veritymode != enforcing` | NAT | H | med | Spoofable via resetprop — pair with `ROOT_PROP_SPOOF`; authoritative version comes from Play Integrity (`SRV`) |
| `ROOT_SELINUX_PERMISSIVE` | Read `/sys/fs/selinux/enforce` | NAT | M | low | Also faked by some hiding modules |
| `ROOT_RW_SYSTEM` | Parse `/proc/mounts` for `rw` on `/system`, `/vendor`, `/product` | NAT | H | low | — |
| `ROOT_MOUNT_ANOMALY` | Unexpected `overlay`/`tmpfs`/bind mounts over system paths; mount-count and namespace divergence vs. `/proc/1/mounts` | NAT | M | med | Detects Magisk-style namespace tricks; some OEMs use overlays legitimately |
| `ROOT_SU_EXEC` | `Runtime.exec("which su")` / attempt to spawn `su` | JVM | L | med | Noisy, may pop a root prompt — **disabled by default**, opt-in only |
| `ROOT_UID_ZERO` | Current UID/GID is 0, or `/proc/self/status` shows unexpected capabilities | NAT | H | low | Should never happen in a normal app |
| `ROOT_INIT_ARTEFACTS` | `.rc` files in `/data/adb`, `su.d`, `init.d` scripts, `/data/adb/service.d` | NAT | M | low | — |

## 2. Hooking, instrumentation & debugging

| SignalId | Technique | Layer | Weight | FP | Notes / known bypass |
| --- | --- | --- | --- | --- | --- |
| `HOOK_FRIDA_MAPS` | Scan `/proc/self/maps` for `frida-agent`, `frida-gadget`, `gum-js-loop`, `linjector`, `re.frida.server`, and for RX regions with no backing file | NAT | H | low | Attacker renames the agent and scrubs maps — pair with memory-fingerprint scan |
| `HOOK_FRIDA_THREADS` | Read `/proc/self/task/*/comm` for `gmain`, `gdbus`, `gum-js-loop`, `pool-frida`, `pool-spawner` | NAT | H | low | Thread names are patchable in a custom frida build |
| `HOOK_FRIDA_PORT` | TCP connect to `127.0.0.1:27042/27043`; on connect, send a D-Bus `AUTH` line and match the expected server reply | NAT | H | low | Frida can run on a random port or over USB only; a positive is near-conclusive, a negative means nothing |
| `HOOK_FRIDA_PORTSCAN` | Optional scan of a bounded local-port range with the D-Bus handshake | NAT | M | low | Expensive → `FULL` depth only; rate-limited |
| `HOOK_FRIDA_ARTEFACTS` | `/data/local/tmp/re.frida.server`, `frida-server*`, `linjector` files, named pipes and abstract sockets matching frida patterns in `/proc/net/unix` | NAT | M | low | — |
| `HOOK_FRIDA_MEMSCAN` | Scan executable regions for agent fingerprints (`frida:rpc`, GumJS strings, script magic) | NAT | H | low | Costly; `FULL` only; obfuscated frida builds evade |
| `HOOK_XPOSED_STACK` | Throw and inspect the stack trace for `de.robv.android.xposed.*`, `LSPosed`, `EdXposed` frames | JVM | H | low | The oldest trick; still catches unhidden setups |
| `HOOK_XPOSED_CLASSES` | `Class.forName("de.robv.android.xposed.XposedBridge")` and helpers on all classloaders | JVM | M | low | Hidden by LSPosed's own anti-detection |
| `HOOK_XPOSED_ARTEFACTS` | `XposedBridge.jar`, `/system/framework/XposedBridge.jar`, Riru/Zygisk module dirs, `app_process` modification | NAT | M | low | — |
| `HOOK_ART_METHOD_ANOMALY` | Sample security-critical Java methods; verify they are not unexpectedly `native`, and that entry points fall inside the expected OAT/DEX ranges (`LSPlant`/`YAHFA`/`Pine` fingerprint) | NAT | H | med | Requires per-ART-version knowledge; gate on known Android versions and emit `INCONCLUSIVE` otherwise |
| `HOOK_INLINE_PROLOGUE` | Compare first bytes of critical `libc`/`libart` symbols (`open`, `read`, `strstr`, `dlopen`, `JNI_*`) against expected instruction patterns; detect trampolines (`B/BR x16`, `LDR PC`) | NAT | H | med | Legitimate vendor instrumentation exists on a few ROMs; allowlist by module path |
| `HOOK_PLT_GOT` | Verify GOT entries for imported symbols resolve inside their owning module's address range | NAT | H | low | — |
| `HOOK_UNEXPECTED_MODULE` | Modules in `/proc/self/maps` outside allow-listed prefixes (app lib dir, `/system`, `/apex`, `/vendor`) | NAT | M | med | Some OEMs inject their own libraries — needs a curated allowlist |
| `HOOK_DEBUGGER_ATTACHED` | `Debug.isDebuggerConnected()`, `Debug.waitingForDebugger()` | JVM | M | low | Trivially hooked |
| `HOOK_TRACER_PID` | `/proc/self/status: TracerPid != 0` | NAT | H | low | Catches ptrace-based debuggers and injectors |
| `HOOK_PTRACE_SELF` | Self-`ptrace` (fork a watchdog that attaches first) to deny later attachment | NAT | I | med | Defensive measure as much as a detection; interacts with crash reporters — opt-in |
| `HOOK_JDWP_ENABLED` | JDWP thread present / `ro.debuggable` + app debuggable flag | NAT | M | low | — |
| `HOOK_SUBSTRATE` | `libsubstrate.so`, `com.saurik.substrate` artefacts | NAT | L | low | Legacy |
| `HOOK_LDPRELOAD` | Inspect `/proc/self/environ` for `LD_PRELOAD` / `LD_LIBRARY_PATH` injection | NAT | H | low | — |

## 3. App integrity & tampering

| SignalId | Technique | Layer | Weight | FP | Notes / known bypass |
| --- | --- | --- | --- | --- | --- |
| `APP_SIGNATURE_MISMATCH` | `GET_SIGNING_CERTIFICATES` → SHA-256 of `apkContentsSigners` (and `signingCertificateHistory`) compared to pinned values | JVM | H | low | **Must** account for Play App Signing and key rotation; verify in native too, since PackageManager is hookable |
| `APP_PACKAGE_MISMATCH` | `context.packageName` vs. compiled-in expected name | JVM+NAT | H | low | Catches renamed clones |
| `APP_INSTALLER_UNEXPECTED` | `getInstallSourceInfo().installingPackageName` not in the allowed set (`com.android.vending`, enterprise MDM, …) | JVM | L | high | Sideloading is legitimate in many markets — informational unless the product is Play-only |
| `APP_DEX_DIGEST_MISMATCH` | Digest each `classes*.dex` entry in the running APK against baselines injected at build time by `integrity-baseline-plugin` | NAT | H | low | Handles split APKs by digesting every loaded source; a re-signed patched APK fails this |
| `APP_NATIVE_LIB_MISMATCH` | Digest the SDK's own `.so` files and verify they load from the app's lib dir | NAT | H | low | Detects `.so` swap |
| `APP_UNEXPECTED_DEX` | `DexPathList` / classloader inspection and maps scan for `.dex`/`.oat`/`.vdex` loaded from `/data/local/tmp`, `/sdcard`, or another package's dir | NAT | H | med | Some legitimate SDKs load DEX dynamically — allowlist |
| `APP_DEBUGGABLE_FLAG` | `ApplicationInfo.FLAG_DEBUGGABLE` set in a release build | JVM | H | low | Set by repackagers to attach a debugger |
| `APP_RESOURCE_TAMPER` | Digest of critical assets (pinned certificates, config, keys) | JVM | M | low | Scope to a small, declared asset list — hashing everything is slow |
| `APP_PROCESS_NAME_ANOMALY` | Process name/`cmdline` does not match the package or expected subprocesses | NAT | M | med | Multi-process apps and WebView processes are normal — allowlist known suffixes |
| `APP_TASK_HIJACK_RISK` | `launchMode`/`taskAffinity` posture usable for StrandHogg-style hijack | JVM | I | low | Configuration advisory for the host, not a device signal |

## 4. Hostile co-installed apps & environment

> Subject to Android 11+ package visibility. See
> [INTEGRATION.md](INTEGRATION.md#package-visibility-android-11). If visibility is not granted,
> these emit `INCONCLUSIVE`, **never** "clean".

| SignalId | Technique | Layer | Weight | FP | Notes |
| --- | --- | --- | --- | --- | --- |
| `ENV_PATCHER_APP` | Declared `<queries>` probe for APK patchers (Lucky Patcher family: `com.chelpus.*`, `com.dimonvideo.luckypatcher`, `com.forpda.lp`, …) | JVM | H | low | Presence is a strong intent signal |
| `ENV_MEMORY_EDITOR` | GameGuardian and clones, `Cheat Engine`-style tools, ptrace-based editors | JVM | H | low | Very strong for games/wallets |
| `ENV_MITM_PROXY_APP` | HttpCanary, Packet Capture, PCAPdroid, Charles, Reqable and similar | JVM | M | med | Developers and QA legitimately install these |
| `ENV_HOOK_MANAGER_APP` | Xposed/LSPosed managers, VirtualXposed, Riru manager, Frida clients | JVM | H | low | — |
| `ENV_CLONER_APP` | Parallel Space, Dual Space, Island, Shelter, App Cloner, VirtualApp derivatives | JVM | M | med | Cloners are mainstream in some markets |
| `ENV_FRIDA_SERVER_DROP` | Executable files in `/data/local/tmp` matching frida/objection patterns | NAT | H | low | Requires the file to be readable — often is |
| `ENV_ADB_ENABLED` | `Settings.Global.ADB_ENABLED`, `Settings.Global.DEVELOPMENT_SETTINGS_ENABLED` | JVM | L | high | Extremely common among developers; informational alone, meaningful in combination |
| `ENV_ADB_OVER_NETWORK` | `service.adb.tcp.port` set / wireless debugging enabled | NAT | M | med | Stronger than plain ADB |
| `ENV_USER_CA_INSTALLED` | User-trust-store certificates present (`/data/misc/user/0/cacerts-added`, `KeyStore` "user" aliases) | JVM | M | high | Corporate MDM installs these legitimately. **Never** block on this alone; prefer certificate pinning in the host's network layer |
| `ENV_PROXY_CONFIGURED` | System HTTP proxy properties / `ConnectivityManager` proxy info | JVM | L | high | Corporate networks |
| `ENV_VPN_ACTIVE` | A `TRANSPORT_VPN` network or `tun0`/`ppp0` interface | JVM | I | high | Millions of legitimate VPN users. Informational only |
| `ENV_ACCESSIBILITY_SERVICE` | Enabled accessibility services not on the host's allowlist, with package names hashed in the report | JVM | M | **high** | **Handle with care.** Screen readers and switch access are assistive tech; never block a user for using them. Use only as a *combination* signal or for RAT-specific packages |
| `ENV_OVERLAY_DETECTED` | `MotionEvent.FLAG_WINDOW_IS_OBSCURED` / `FLAG_WINDOW_IS_PARTIALLY_OBSCURED` on sensitive views; `filterTouchesWhenObscured` | JVM | H | med | Best used at the moment of a sensitive tap, not as a background poll |
| `ENV_SCREEN_CAPTURE_ACTIVE` | MediaProjection/cast session active while a sensitive screen is shown | JVM | M | med | Legitimate screen recording exists |
| `ENV_UNKNOWN_SOURCES` | `canRequestPackageInstalls()` / install-unknown-apps permission granted to a non-store app | JVM | L | high | — |
| `ENV_PLAY_PROTECT_OFF` | From Play Integrity `environmentDetails.playProtectVerdict` | SRV | M | low | Server-verified; no client equivalent |

## 5. Emulator, cloud phone & virtual container

| SignalId | Technique | Layer | Weight | FP | Notes |
| --- | --- | --- | --- | --- | --- |
| `EMU_BUILD_FINGERPRINT` | `Build.FINGERPRINT/MODEL/MANUFACTURER/PRODUCT/HARDWARE/BOARD` matching `generic`, `goldfish`, `ranchu`, `sdk_gphone`, `vbox`, `emulator`, `cuttlefish` | JVM+NAT | H | low | Spoofable; cheap first filter |
| `EMU_QEMU_ARTEFACTS` | `/dev/qemu_pipe`, `/dev/socket/qemud`, `ro.kernel.qemu`, `qemu.*` props, `/system/lib/libc_malloc_debug_qemu.so` | NAT | H | low | — |
| `EMU_HW_SANITY` | No accelerometer/gyroscope; battery permanently 100% on AC; no telephony/IMEI; fixed sensor values | JVM | M | med | Tablets and some devices legitimately lack sensors |
| `EMU_CPU_ANOMALY` | `/proc/cpuinfo` lacking expected ARM fields; x86 host running ARM app via translation (`houdini`, `libnb`) | NAT | M | med | ChromeOS and Windows Subsystem for Android are legitimate |
| `EMU_CLOUD_PHONE` | redroid/container fingerprints: missing `/dev` nodes, container cgroups, unusual `ro.boot.*` | NAT | H | med | Overlaps with `VIRT_CONTAINER` |
| `VIRT_DUAL_INSTANCE` | Own package data path is not `/data/user/0/<pkg>`, or a foreign package path prefixes the app's own files | NAT | H | med | Work profile (`/data/user/10/…`) is legitimate — distinguish via `UserManager`/`isProfile` before scoring |
| `VIRT_PARENT_NOT_ZYGOTE` | `/proc/self/stat` parent process is not `zygote`/`zygote64` | NAT | H | med | — |
| `VIRT_FOREIGN_PACKAGE_MAPS` | Another package's APK/lib paths mapped into this process | NAT | H | low | Classic VirtualApp fingerprint |
| `VIRT_UID_ANOMALY` | Process UID's app-id does not match the package's declared UID, or multiple instances of the package's process exist | NAT | M | med | — |

## 6. Attestation (server-verified)

| SignalId | Source | Layer | Weight | FP | Notes |
| --- | --- | --- | --- | --- | --- |
| `ATT_DEVICE_INTEGRITY_FAIL` | Play Integrity `deviceRecognitionVerdict` lacks `MEETS_DEVICE_INTEGRITY` | SRV | H | low | The single most reliable root/bootloader signal available |
| `ATT_BASIC_INTEGRITY_FAIL` | Lacks `MEETS_BASIC_INTEGRITY` | SRV | H | low | — |
| `ATT_VIRTUAL_ONLY` | Only `MEETS_VIRTUAL_INTEGRITY` (emulator with a genuine Play image) | SRV | M | low | Legitimate for developers/ChromeOS |
| `ATT_APP_NOT_RECOGNISED` | `appIntegrity.appRecognitionVerdict != PLAY_RECOGNIZED` | SRV | H | low | Direct repackaging/sideload evidence |
| `ATT_APP_ACCESS_RISK` | `environmentDetails.appAccessRiskVerdict` reports capturing/controlling apps | SRV | H | low | Google's own view of overlay/a11y/screen-capture risk — prefer over client heuristics where available |
| `ATT_UNEVALUATED` | Token unavailable, Play Services missing, or verification failed | SRV | M | med | Treat "unevaluated" as risk, not as clean — but expect it in non-GMS markets |

## 7. Meta signals

| SignalId | Meaning |
| --- | --- |
| `META_DETECTOR_TIMEOUT` | A detector exceeded its budget — evidence lost, possibly deliberate |
| `META_DETECTOR_ERROR` | A detector threw; includes the exception class only |
| `META_NATIVE_UNAVAILABLE` | Native library failed to load or its self-check failed — **high suspicion**, since removing the `.so` is a common bypass |
| `META_VISIBILITY_RESTRICTED` | Package visibility denied, so `ENV_*` results are incomplete |
| `META_CONFIG_INVALID` | Host misconfiguration (e.g. no signing pin supplied) |

---

## Adding a new signal — checklist

1. Add the `SignalId` constant with a stable string.
2. Add a row to the right section here: technique, layer, weight, FP risk, known bypass.
3. Implement in the owning detector module; native where a JVM implementation is trivially
   hookable.
4. Unit test the parsing logic against captured fixtures (real `/proc` dumps in
   `integrity-testing`).
5. Instrumented test: at least one positive device/condition and one clean device.
6. FP analysis: name at least one legitimate configuration that could trigger it, and state
   why the weight is safe (or add an allowlist).
7. Default the weight conservatively. New signals ship at `I` (informational) and are
   promoted after shadow-mode telemetry supports it.
