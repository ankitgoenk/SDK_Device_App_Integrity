# Device & App Integrity SDK (Android)

A modular, Kotlin-first Android SDK that answers two questions for the host app at runtime:

1. **Is this device trustworthy?** — root / Magisk / KernelSU, Frida and other dynamic
   instrumentation, Xposed-family hooking, emulators, cloud phones and virtualised
   ("app cloning") containers.
2. **Is this app still the app we shipped?** — signature and code tampering, repackaging,
   debuggers, injected libraries, and *other installed apps* whose purpose is to modify,
   observe or scramble app behaviour (patchers, memory editors, MITM proxies, cloners,
   abusive accessibility services, screen overlays).

The SDK produces an **evidence-based report**, not a boolean. The host app — and ideally the
host's **backend** — decides what to do with it.

> **Status:** phase 0 complete — the multi-module scaffold, public API skeleton, quality
> gates and CI are in place. Detectors land in phases 2–7 and every `evaluate()` currently
> returns `UNKNOWN`. Start with [`docs/PLAN.md`](docs/PLAN.md).

---

## Documentation map

| Document | What it covers |
| --- | --- |
| [docs/PLAN.md](docs/PLAN.md) | **Start here.** Phased plan of action, milestones, deliverables, estimates |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Who the adversary is, what they can do, what this SDK can and cannot promise |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Module layout, execution engine, threading, native/JVM split |
| [docs/DETECTION_CATALOG.md](docs/DETECTION_CATALOG.md) | Every detection signal: technique, weight, false-positive risk, known bypass |
| [docs/RISK_SCORING.md](docs/RISK_SCORING.md) | How signals become a score and a verdict; policy configuration; FP tuning |
| [docs/API_DESIGN.md](docs/API_DESIGN.md) | Public Kotlin/Java API surface, data model, lifecycle |
| [docs/INTEGRATION.md](docs/INTEGRATION.md) | Host-app integration: Gradle, manifest, `<queries>`, R8, response patterns |
| [docs/SERVER_VERIFICATION.md](docs/SERVER_VERIFICATION.md) | Signed reports, nonces, Play Integrity, backend decisioning |
| [docs/ANTI_TAMPER.md](docs/ANTI_TAMPER.md) | Protecting the SDK itself from being neutered |
| [docs/PRIVACY_AND_COMPLIANCE.md](docs/PRIVACY_AND_COMPLIANCE.md) | Play policy, permissions, GDPR/DPDP, data minimisation |
| [docs/TESTING.md](docs/TESTING.md) | Device matrix, rooted/Frida test rigs, CI, red-team bypass drills |
| [docs/adr/](docs/adr/) | Architecture decision records |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Conventions, branch/commit rules, review checklist |

## Design principles

1. **Evidence over verdicts.** Every check emits a typed `Signal` with confidence and
   supporting detail. Scoring is a separate, configurable layer.
2. **Never block the UI, never crash the host.** Every detector runs under a time budget in a
   sandboxed executor; a detector that throws or hangs degrades to `INCONCLUSIVE`.
3. **Client checks are speed bumps; the server is the referee.** Anything that matters is
   re-decided on the backend against a signed, nonce-bound report plus Play Integrity.
4. **False positives are bugs.** A legitimate user on a Chinese OEM ROM with a work profile and
   a screen reader must not be locked out. Every signal ships with an FP analysis.
5. **Silent by default.** The SDK detects and reports; it never shows UI, never kills the
   process, and never phones home without the host configuring a sink.
6. **Layered response.** Detection and reaction are decoupled in time and code location so a
   single patched branch does not disable enforcement.

## Non-goals

- DRM, licence enforcement, or blocking legitimate power users on principle.
- Collecting the full installed-app inventory (privacy- and policy-hostile — see
  [PRIVACY_AND_COMPLIANCE.md](docs/PRIVACY_AND_COMPLIANCE.md)).
- Claiming unbypassable protection. A determined attacker with a rooted device and time wins
  the client-side battle; the goal is cost, telemetry, and server-side leverage.

## Quick shape of the API (target)

```kotlin
IntegrityGuard.initialize(
    context,
    IntegrityConfig.Builder()
        .expectedSigningCertSha256("A1:B2:…")
        .policy(Policy.balanced())
        .reportSink(MyBackendSink())
        .build()
)

// Fast, cached, safe to call on a hot path
val report = IntegrityGuard.currentReport()

// Full async sweep
lifecycleScope.launch {
    val fresh = IntegrityGuard.evaluate(Depth.FULL)
    if (fresh.verdict == Verdict.COMPROMISED) escalateToBackend(fresh.signedPayload)
}
```

## Building

```bash
./gradlew build                 # assemble + unit tests + lint
./gradlew detekt ktlintCheck    # static analysis
./gradlew apiCheck              # public API surface is contract (apiDump to regenerate)
tools/check-signal-catalog.py   # every SignalId must be documented in the catalog
```

Requires JDK 17+ and an Android SDK (`compileSdk 35`). `tools/setup-dev-env.sh` reports what
is missing; it also runs automatically as a `SessionStart` hook in Claude Code sessions.

The NDK is only needed from phase 3, so `:integrity-native` is excluded from the build until
you set `integrity.enableNative=true`.

### Modules

| Module | Purpose |
| --- | --- |
| `integrity-core` | Public API, data model, engine, scoring. No detectors |
| `integrity-native` | C++ core: `/proc` scanning, code-integrity checks, string vault (phase 3) |
| `integrity-detector-{root,hooking,app,environment,emulator}` | Signal families, one module each |
| `integrity-attestation-play` | Play Integrity wrapper (phase 7) |
| `integrity-baseline-plugin` | Gradle plugin that bakes digests and pins at build time (phase 4) |
| `integrity-testing` | Fakes and fixtures for detector tests |
| `sample-app` | Renders a live report |
| `sample-backend` | Nonce issuance and report verification (phase 7) |

## Licence

TBD before first public release (see [docs/PLAN.md](docs/PLAN.md), Phase 11).
