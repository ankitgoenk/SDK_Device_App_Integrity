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

A detector whose positive fixture cannot be produced honestly is not ready to be written.
Design it first, in `docs/detectors/<SIGNAL_ID>.md`, and get the known bypass and the
positive fixture reviewed before any implementation exists — both are far easier to argue
away once there is code to defend. `docs/detectors/HOOK_SELF_TEXT_MISMATCH.md` is the
worked example.

**Ask the fixture question at catalogue time, not at implementation time.** The rule above
is written as a build-time gate, and by then it is too late to be cheap: 84 candidates
entered `docs/DETECTION_CATALOG.md` before anyone asked where their positive fixtures would
come from, and `docs/DETECTION_TRIAGE.md` exists to pay that debt down afterwards. A new
catalogue row should say, in its own words, **what configuration makes this fire**. If the
answer is "no hardware we have", that is a legitimate row — it belongs on the procurement
list at the end of the triage doc, not on the backlog.

**Match the control to the attacker, not to the rooted phone.** The reference Pixel is the
right control for `ROOT_*` and `HOOK_*` and the wrong one for `APP_TAMPER`, whose attacker is
a repackaged app on an ordinary unrooted device. `APP_DEX_DIGEST_MISMATCH` ships with a
synthetic tampered archive as its positive control and is stronger for it. "Demonstrate a
device where it fires" is the right instinct with the wrong noun: demonstrate a *condition*
where it fires, on whatever substrate that condition actually lives.

Four of these are enforced by `tools/check-signal-catalog.py` in CI: a `SignalId` in
production code must have a catalog row, that row must state a technique, a false-positive
risk and a known bypass, and at least one unit test must reference the signal by name.
The rest is review, because a checker that guessed at them would only teach people how to
satisfy the checker.

### Testing around the "couldn't verify" state

Every detector has a state meaning *I could not check this*: `Confidence.INCONCLUSIVE` in
Kotlin, `kStatusUnavailable` in native. Hard rule 2 requires it and it is the right default —
but it gives every detector a safe-looking state that a **bug** can produce just as easily as
a legitimate one, and ordinary tests cannot tell the two apart.

A test asserting `INCONCLUSIVE` where the check legitimately cannot run passes whether the
detector works or not. The suite stays green while the detector has quietly stopped
detecting. This is not hypothetical: `off_t` truncation on 32-bit ABIs did exactly this to
`readSelfMemory`, and the entire native suite passed with the bug present (ADR-0005, 3b).

So, wherever a bug would produce the same result as a legitimate "couldn't verify":

> **Assert a relative property proving the check succeeds when it should, rather than merely
> asserting the failure is absent.**

Three parts, all of them load-bearing:

1. **Prove the positive.** Where the check *can* run, assert the conclusive result — not the
   absence of a failure.
2. **Guard against vacuity.** If the assertion is conditional, assert that its precondition
   actually held. A conditional check that silently skips is a green result proving nothing.
3. **Make skips visible, and skip only when the capability is genuinely absent.** When a
   check legitimately cannot run, say so in the output, so a run where the property was
   exercised is distinguishable from one where it was not.

   Visible is not the same as acceptable, and the second half of this rule was learned the
   hard way. A test that skips whenever the thing under test reports "unavailable" passes
   against an implementation that reports unavailable *everywhere* — announcement and all.
   Establish the prerequisites first: absent, skip and say so; present, require the check
   to complete.

"I don't know" must never be able to masquerade as "everything is fine" — not in a report to
the host app, and not in CI.

**And the general form of all three: mutation testing.** Each rule above is a way of asking
"did that test actually test anything?", and each has to be applied by hand, case by case.
`tools/mutate-native.py` asks it mechanically: it breaks the native code in a specific way
and requires the suite to notice. A mutant nothing catches is a hole in the tests, not a
defect in the code, and the mutation score is the honest measure of the native suite — case
counts are only an input to it. Adding a check that the property tests pass is easy; adding
one that fails when the code is wrong is the point.

Three configurations, because a defect can be invisible in two of them: plain, 32-bit (some
bugs exist only at one pointer width), and AddressSanitizer (some changes return identical
values for every input and are still memory-unsafe). The driver reports a mutant it could
not try separately from one it failed to catch — untried is not uncaught.

- [ ] Implementation in the correct module (native where a JVM implementation is trivially hookable)
- [ ] `SignalId` constant with a stable string, plus a complete row in `docs/DETECTION_CATALOG.md`
- [ ] Unit tests against fixtures in `integrity-testing/fixtures/`
- [ ] Instrumented test: one positive condition, one clean condition
- [ ] Where a bug would return the same result as a legitimate "couldn't verify", a
      relative property proves the check actually ran (see above)
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
4. Could a bug in this detector return `INCONCLUSIVE` too — and would any test notice?
5. What does this signal share with the ones already promoted — the primitive it reads
   through, the file it trusts, the interface it depends on? Signals that fail to the same
   cause are one input, not several (see `docs/RISK_SCORING.md`).
6. Does the evidence map contain anything that could identify a person or device?
7. Is the worst-case runtime bounded, and is the budget realistic on a low-end device?
8. Does the catalog entry describe a known bypass honestly?

## Security issues

Do not open a public issue for a bypass or vulnerability. Follow the disclosure process in
`SECURITY.md` (to be added in Phase 11).
