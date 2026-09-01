# Repository guide

Android SDK for device- and app-integrity detection (root, Frida/hooking, tampering,
hostile co-installed apps), plus the backend half that turns its evidence into a decision.

**Status:** phases 0–1 and 7 complete; 2 and 3 in progress. Twelve modules, a shipped native
core, a backend challenge-and-decision pipeline, and signed reports verified server-side.
Eight device detections are live against a catalogue of 68 — the other nine `SignalId`s in
code are `META_*` (the SDK reporting on itself, seven of them), `ATT_*` (server-side vocabulary
we never emit) and `SRV_REPORT_SIGNATURE_INVALID` (server-side, and we do emit it), so "17
implemented" from the catalogue gate is not seventeen detections. Run `tools/check-signal-catalog.py` for the
current count.

## Where things are

- `docs/PLAN.md` — phased plan of action; the source of truth for what to build next
- `docs/DETECTION_CATALOG.md` — every signal; **any new `SignalId` must be added here**
- `docs/ARCHITECTURE.md` — module layout and execution model; follow it when scaffolding
- `docs/SERVER_VERIFICATION.md` — the backend half: challenge lifecycle, decision pipeline
- `docs/adr/` — decisions that should not be relitigated without a new ADR. ADR-0006 is the
  integration contract; **ADR-0007 is the asymmetric-trust rule** that governs the backend;
  **ADR-0008 puts attestation out of scope**, which is why the backend has no `TRUSTED` state
  and emits no access action; **ADR-0011 applies the asymmetry to report signing** — a valid
  signature may never improve a finding, and a failed one may never suppress evidence
- `tools/` — the CI gates. Several of them test the other gates; see `mutate-backend.py`

## Hard rules when writing code here

1. No main-thread file, socket or `PackageManager` IO. Ever.
2. A check that cannot run returns `Confidence.INCONCLUSIVE` — never an empty result implying
   "clean".
3. No PII in signal evidence: no IMEI/ANDROID_ID/MAC/location/accounts; third-party package
   names are hashed before leaving the device.
4. Never declare `QUERY_ALL_PACKAGES` (see ADR-0004).
5. The SDK performs no network IO (ADR-0003) and never terminates the host process.
6. New signals ship at `INFORMATIONAL` weight until shadow-mode data justifies promotion.
   Two gates block the first non-zero weight, and neither is the promoter's to waive: report
   signing must be shipped and verified (**done** — ADR-0011), and the reports must be joinable
   to authoritative fraud outcomes (**still open, and the harder one**). Promote on
   **precision at the operating point**, never on hit rate. The join key comes from the host —
   adding a device identifier to the report to make the join easier breaks hard rule 3. See "Weight promotion" at the end of `docs/PLAN.md` §1.
7. `integrity-core` takes no third-party runtime dependency beyond coroutines and
   `androidx.annotation`.
8. **The client may report evidence and consume a server decision. It must never treat the
   absence of evidence, the absence of a server response, or a locally computed verdict as
   proof that the device is trusted.** The SDK says what it observed; the backend decides.
   See ADR-0006.
9. **Evidence can incriminate. It can never exonerate.** A detector that finds nothing emits
   no signal, so a clean device and a client suppressing everything send identical reports.
   Server-side, signals may only move a decision away from trust. Never add a path where
   something in the report raises trust — including a client-supplied `coverage`. See ADR-0007.
   This project performs **no attestation** and its backend has no `TRUSTED` state and no
   access action: it grades evidence, the integrator decides. Do not add an `ALLOW` back
   without a new ADR — see ADR-0008. **Neither vocabulary may contain a name a caller could
   read as permission**: `Verdict` (client) and `DeviceState` (server) both had a `TRUSTED`
   rung and both lost it, and a test pins the membership of each. See ADR-0009.
10. A gate that cannot fail is worse than no gate. Anything asserting a security property
   ships with proof it rejects the broken case: a positive control, a deliberately broken
   implementation the suite must catch, or a mutant. This has caught more real defects here
   than code review has.

## Conventions

Kotlin official style, ktlint + detekt, conventional commits, one signal family per PR.
See `CONTRIBUTING.md` for the detector definition-of-done.

**Keep these docs current in the same PR as the change.** `docs/PLAN.md` phase markers,
`docs/adr/0006`'s CI-enforcement checklist, the module tables in `README.md` and
`docs/ARCHITECTURE.md`, and `docs/DETECTION_TRIAGE.md`'s verdicts have all gone stale before —
the triage within hours of a merge, calling a shipped detector "BUILD (blocked)" on a
dependency that had already landed. Two of those now fail the build:
`tools/check-doc-drift.py` for the module tables and `tools/check-triage-consistency.py` for
the triage's `BUILT` verdicts and its census arithmetic. The phase markers and the ADR-0006
checklist are still on you.
