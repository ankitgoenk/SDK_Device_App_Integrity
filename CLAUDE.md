# Repository guide

Android SDK for device- and app-integrity detection (root, Frida/hooking, tampering,
hostile co-installed apps). **Currently design-phase: documentation only, no code yet.**

## Where things are

- `docs/PLAN.md` — phased plan of action; the source of truth for what to build next
- `docs/DETECTION_CATALOG.md` — every signal; **any new `SignalId` must be added here**
- `docs/ARCHITECTURE.md` — module layout and execution model; follow it when scaffolding
- `docs/adr/` — decisions that should not be relitigated without a new ADR

## Hard rules when writing code here

1. No main-thread file, socket or `PackageManager` IO. Ever.
2. A check that cannot run returns `Confidence.INCONCLUSIVE` — never an empty result implying
   "clean".
3. No PII in signal evidence: no IMEI/ANDROID_ID/MAC/location/accounts; third-party package
   names are hashed before leaving the device.
4. Never declare `QUERY_ALL_PACKAGES` (see ADR-0004).
5. The SDK performs no network IO (ADR-0003) and never terminates the host process.
6. New signals ship at `INFORMATIONAL` weight until shadow-mode data justifies promotion.
7. `integrity-core` takes no third-party runtime dependency beyond coroutines and
   `androidx.annotation`.
8. **The client may report evidence and consume a server decision. It must never treat the
   absence of evidence, the absence of a server response, or a locally computed verdict as
   proof that the device is trusted.** The SDK says what it observed; the backend decides.
   See ADR-0006.

## Conventions

Kotlin official style, ktlint + detekt, conventional commits, one signal family per PR.
See `CONTRIBUTING.md` for the detector definition-of-done.
