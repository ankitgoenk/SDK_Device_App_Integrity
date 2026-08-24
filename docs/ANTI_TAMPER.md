# Protecting the SDK Itself

A detection SDK is the first thing an attacker attacks. The goal is not invulnerability — it
is to make bypass **expensive, multi-step, and visible to the backend**.

## 1. No single point of failure

Bad:

```kotlin
val rooted = RootDetector.check()          // one call site, one boolean, one patch
if (rooted) block()
```

Good:
- Multiple **independent implementations** of the highest-value checks (JVM + native +
  attestation) that must all be defeated.
- No single `isCompromised` boolean anywhere in the code path. Risk travels as a score
  embedded in a larger structure, recomputed in more than one place.
- Verdicts are recomputed on the backend from raw signals, so patching client scoring
  achieves nothing.

## 2. Keep the crown jewels in native code

- All artefact strings (paths, package names, port numbers, symbol names) live in an
  XOR-obfuscated **string vault** generated at build time by `integrity-baseline-plugin` with a
  per-build key. `strings libintegrity.so` yields nothing useful.
- Compile with `-fvisibility=hidden`, `-ffunction-sections -Wl,--gc-sections`, LTO, and strip
  all symbols. Register JNI methods dynamically in `JNI_OnLoad`; do not export
  `Java_io_integrity_…` names an attacker can grep for.
- Avoid `libc` wrappers where cheap: prefer raw `syscall()` for `openat`/`read`/`stat` in the
  most critical probes, so a `libc` PLT hook does not silently blind them.
- Detect the absence of the native layer: `META_NATIVE_UNAVAILABLE` is scored as a high-risk
  signal, because deleting the `.so` is the laziest bypass.

## 3. Self-verification

- Native code verifies its own text-segment digest against a build-time baseline.
- The SDK verifies the host APK's dex/lib digests (`APP_DEX_DIGEST_MISMATCH`) — patching the
  SDK's Kotlin means repackaging the APK, which the digest and signature checks catch, and
  which Play Integrity catches independently.
- Result objects are **tamper-evident**: `IntegrityReport` carries a MAC over its own fields
  computed natively at construction; the signing path re-verifies it, so mutating a report
  after the fact invalidates the signature rather than silently passing.

## 4. Make hooking the API useless

- The signed payload is produced natively from the raw signal list, not from the public Kotlin
  objects. Hooking `evaluate()` to return a clean `IntegrityReport` does not produce a valid
  signature the backend will accept.
- Bind the report to the nonce inside the native signer; a replayed clean payload fails the
  nonce check.
- Ship a **honeypot**: an obvious, easily-hooked public method (`isDeviceRooted()`) whose
  return value is not used in the real decision path. Its invocation with a hooked result is
  itself reported as a signal (`HOOK_HONEYPOT_TRIGGERED`, registered as informational until
  validated).

## 5. Decouple detection from response

Reacting at the point of detection gives the attacker a stack trace straight to the check.
Instead:

- Detect → record → return normally.
- Report asynchronously; let the **backend** decide.
- Degrade later, in unrelated code (a feature flag flipped on the next server response, a
  transaction declined server-side), never `System.exit()` at the detection site.
- Add jitter: randomise which detectors run in a given pass and when reports are sent, within
  the configured budget, so behaviour cannot be trivially correlated with a check.

## 6. Build-time hardening

| Measure | Implementation |
| --- | --- |
| R8 full mode with aggressive renaming for SDK internals | Consumer rules keep only what reflection needs |
| No debug symbols, no line numbers in release | `-dontwarn`, strip `SourceFile` |
| String obfuscation | Baseline plugin (native vault + JVM constant folding) |
| Control-flow redundancy on critical paths | Duplicate checks with different implementations, compare results |
| Reproducible baselines | Digests computed post-packaging, verified in CI so a mismatch fails the build |
| No logging in release | `IntegrityLogger` is a no-op unless the host supplies one; never log signal internals |

## 7. What we deliberately do **not** do

- **No commercial packer/VMP.** Heavy, breaks on OEM ROMs, blows up crash reporting, and buys
  time rather than security. Revisit only if telemetry proves the need.
- **No anti-emulator hard blocks.** Breaks CI, ChromeOS and legitimate testers.
- **No self-crashing / `System.exit()`.** Turns a detection into a support incident and a
  clean attacker breakpoint.
- **No silent data exfiltration.** The SDK has no network stack by design.
- **No ptrace-self by default.** It conflicts with legitimate crash reporters and debuggers;
  opt-in only.

## 8. Measuring effectiveness

At each release, run the bypass drill in [TESTING.md](TESTING.md#red-team-drill) and record,
per attack, the *time-to-bypass* and *number of independent changes required*:

| Attack | Target | Independent changes required (goal) |
| --- | --- | --- |
| Public Frida anti-root script | JVM root checks | ≥ 3 (JVM, native, attestation) |
| Delete the `.so` | Native layer | Caught by `META_NATIVE_UNAVAILABLE` |
| Patch scoring to return `TRUSTED` | Client verdict | Caught server-side (re-scoring) |
| Repackage + re-sign | Everything | Caught by signature, dex digest, and Play Integrity |
| Strip the `evaluate()` call | Integration | Caught by "no report" server-side rule |
| Replay a captured clean payload | Transport | Caught by nonce + freshness |

If any row can be satisfied with one change, that is a defect — file it.
