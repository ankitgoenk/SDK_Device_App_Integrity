# Contributing

## Branching and commits

- Feature work happens on `claude/android-security-detection-sdk-f3c8uh` (current development
  branch) or a topic branch off it.
- Conventional commits: `feat(detector-root): add KernelSU artefact probe`.
- One signal family per PR wherever possible.

## Definition of done for a detector

Every signal ships the whole chain. A signal is only worth as much as what is known about
it, and the parts people skip under deadline — the bypass note and the false-positive
analysis — are the parts that decide whether it is safe to enforce.

```
Signal            a stable SignalId, one family per PR
  ↓
Evidence          what the check observes, and the bounded, non-PII evidence keys it emits
  ↓
Expected result   which Confidence, on which device state, and what INCONCLUSIVE means here
  ↓
Unit test         parser and decision logic, against fixtures
  ↓
Instrumented test where appropriate: one positive condition, one clean device
  ↓
Known bypass      how you would defeat it. "I couldn't" is not an answer; say why it is hard
  ↓
FP analysis       a legitimate configuration that could trigger it, and why the weight is safe
```

Four of these are enforced by `tools/check-signal-catalog.py` in CI: a `SignalId` in
production code must have a catalog row, that row must state a technique, a false-positive
risk and a known bypass, and at least one unit test must reference the signal by name.
The rest is review, because a checker that guessed at them would only teach people how to
satisfy the checker.

- [ ] Implementation in the correct module (native where a JVM implementation is trivially hookable)
- [ ] `SignalId` constant with a stable string, plus a complete row in `docs/DETECTION_CATALOG.md`
- [ ] Unit tests against fixtures in `integrity-testing/fixtures/`
- [ ] Instrumented test: one positive condition, one clean condition
- [ ] Default weight is conservative (new signals ship `INFORMATIONAL` until shadow-mode data
      supports promotion)
- [ ] Per-detector budget respected; no main-thread IO; cancellation-aware
- [ ] No new runtime dependency in `integrity-core`
- [ ] No restricted API usage (see `docs/PRIVACY_AND_COMPLIANCE.md`, section 1)

## Code style

- Kotlin official style, ktlint + detekt enforced in CI.
- Public API changes require an `api/*.api` dump update and explicit review.
- Native: C++17, no exceptions across the JNI boundary, no `abort()`, every parser fuzzed.
- No logging in release paths. `IntegrityLogger` is a no-op unless the host supplies one.

## Review checklist (reviewer)

1. Could this signal fire on a legitimate user? Who?
2. Is the check implemented at the layer that is hardest to hook for its value?
3. Does failure degrade to `INCONCLUSIVE` rather than silently to "clean"?
4. Does the evidence map contain anything that could identify a person or device?
5. Is the worst-case runtime bounded, and is the budget realistic on a low-end device?
6. Does the catalog entry describe a known bypass honestly?

## Security issues

Do not open a public issue for a bypass or vulnerability. Follow the disclosure process in
`SECURITY.md` (to be added in Phase 11).
