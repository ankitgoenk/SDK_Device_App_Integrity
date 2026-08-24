# Contributing

## Branching and commits

- Feature work happens on `claude/android-security-detection-sdk-f3c8uh` (current development
  branch) or a topic branch off it.
- Conventional commits: `feat(detector-root): add KernelSU artefact probe`.
- One signal family per PR wherever possible.

## Definition of done for a detector PR

- [ ] Implementation in the correct module (native where a JVM implementation is trivially hookable)
- [ ] `SignalId` constant with a stable string, plus a row in `docs/DETECTION_CATALOG.md`
- [ ] Unit tests against fixtures in `integrity-testing/fixtures/`
- [ ] Instrumented test: one positive condition, one clean condition
- [ ] False-positive analysis in the PR description: name a legitimate configuration that
      could trigger this and justify the default weight
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
