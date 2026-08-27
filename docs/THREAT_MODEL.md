# Threat Model

## Assets

| Asset | Why an attacker wants it |
| --- | --- |
| Host app's business logic and client-side checks | Bypass paywalls, limits, KYC, anti-cheat, promo abuse |
| Session credentials and tokens in memory | Account takeover, automation at scale |
| Network traffic and API contract | Build headless clients, farm bots, scrape |
| App identity (signature) | Distribute a repackaged trojan or ad-stripped clone |
| The integrity SDK itself | Neutralise it so everything above becomes easy |

## Adversary tiers

| Tier | Capability | Typical tooling | Our objective |
| --- | --- | --- | --- |
| **T0 — Curious user** | Rooted phone, installs modules | Magisk, ad-blockers, Play Store patchers | Detect reliably; usually a *policy* decision, not fraud |
| **T1 — Script kiddie** | Runs public bypass scripts | Frida + Codeshare scripts, Lucky Patcher, Objection | Detect and defeat public one-liners; raise cost to "must customise" |
| **T2 — Competent modder** | Reads the SDK, patches smali/native, writes bespoke hooks | Frida, LSPosed modules, apktool, Ghidra, `radare2` | Cannot be stopped client-side. Make bypass expensive, noisy and detectable server-side |
| **T3 — Organised fraud** | Device farms, cloud phones, emulator fleets, custom ROMs, hardware | redroid, custom AOSP builds, virtualisation frameworks | Detect at the *fleet* level via server-side correlation and attestation, not per-device cleverness |

The SDK is designed to convert T1 into a hard stop, T2 into a measurable cost with strong
server-side signal, and T3 into a backend detection problem for which the SDK supplies
evidence.

## Attack surfaces

### 1. Device environment
- Root via Magisk (with DenyList/Zygisk hiding), KernelSU, APatch, or a permissive custom ROM.
- Bootloader unlocked / verified boot broken / dm-verity disabled.
- SELinux permissive; `ro.debuggable=1` "userdebug" ROMs.
- Property spoofing (`resetprop`) to hide all of the above.

### 2. Dynamic instrumentation
- `frida-server` on the device (default or randomised port, renamed binary).
- `frida-gadget` injected into the APK or loaded via `LD_PRELOAD` / patched `libc`.
- Xposed family: LSPosed/EdXposed via Riru or Zygisk, VirtualXposed in a container.
- Cydia Substrate, custom `ptrace`-based injectors, `libhoudini`-level tricks.
- Java-level hooking via ART method replacement (`LSPlant`, `YAHFA`, `Pine`, `SandHook`).

### 3. App tampering
- Repackaging: decompile, patch smali, re-sign with an attacker key, redistribute.
- Runtime patching of loaded DEX/OAT or native code.
- Injecting an extra DEX/`.so` into the process at runtime.
- Debugger attachment (`jdwp`, `gdb`, `lldb`) and `ptrace`-based memory editing.
- Resource/asset swaps (config, endpoint, pinned certificate replacement).

### 4. Hostile co-installed apps
- **Patchers:** Lucky Patcher and similar — modify installed APKs, block licence checks.
- **Memory editors:** GameGuardian and clones — search/freeze process memory.
- **MITM proxies:** HttpCanary, Packet Capture, Charles/mitmproxy with a user CA.
- **Cloners / virtual spaces:** Parallel Space, Dual Apps, VirtualApp derivatives — run the
  host app inside another app's process with full control over its filesystem view.
- **Accessibility abuse:** a service that reads the screen and injects gestures — the basis
  of most Android remote-access scam and ATO tooling.
- **Overlay attacks:** a window over the host app capturing taps or displaying fake UI.
- **Screen capture / remote control:** MediaProjection-based streaming, TeamViewer-style RAT.

### 5. Attacks on the SDK itself
- Patch `Verdict` construction to always return `TRUSTED`.
- Hook the public API (`evaluate`) and return a cached clean report.
- Strip the SDK's initialisation call from the host app entirely.
- Replace the native `.so` with a stub, or hook `System.loadLibrary`.
- Block or forge the report upload; replay an old clean signed report.

Mitigations for this class are in [ANTI_TAMPER.md](ANTI_TAMPER.md) and
[SERVER_VERIFICATION.md](SERVER_VERIFICATION.md). The short version: assume the client can
lie, so make the *absence* of a valid, fresh, nonce-bound, signed report as suspicious as a
bad one.

## Explicit trust boundaries

| Boundary | Assumption |
| --- | --- |
| SDK ↔ host app | Same process, same trust. The SDK cannot defend against a hostile host |
| SDK ↔ OS | Untrusted on rooted devices. Everything the OS reports may be spoofed |
| Client ↔ backend | Backend trusts nothing from the client. A signed report bound to a server nonce proves freshness and origin, never that its contents are true |
| Backend ↔ attestation | Out of this project's scope (ADR-0008). The integrator runs their own attestation and combines its result with our evidence finding. Wherever it runs, never verify a token on-device |

## What this SDK does **not** promise

1. **It cannot stop a T2+ attacker on their own device.** Anything running in the app's
   process can be modified by someone with root on that device.
2. **It cannot prove a device is clean.** It can only report the absence of evidence — and
   absence is weak evidence, which is why `INCONCLUSIVE` is a first-class result.
3. **It is not a substitute for server-side controls.** Rate limits, anomaly detection,
   server-authoritative business logic and attestation carry the real weight.
4. **It cannot see other apps' internals**, only their presence and coarse metadata, subject
   to Android package-visibility rules.

## Security requirements derived from this model

- **SR1** Every detection result must be attributable to a specific `SignalId` with evidence.
- **SR2** No detection result may be trusted by a backend unless it is signed, fresh and
  bound to a server-issued nonce.
- **SR3** Missing/refused reports must be treated as a risk signal by the backend, not as a
  neutral outcome.
- **SR4** Detection must be redundant across layers (JVM, native, attestation) so no single
  hook disables it.
- **SR5** Response must be decoupled from detection in both time and code location.
- **SR6** No signal may collect more personal data than the decision requires (see
  [PRIVACY_AND_COMPLIANCE.md](PRIVACY_AND_COMPLIANCE.md)).
