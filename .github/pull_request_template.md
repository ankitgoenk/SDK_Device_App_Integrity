## What changed

<!-- One or two sentences. Link the phase in docs/PLAN.md this advances. -->

## Detector PRs only

- [ ] `SignalId` added with a stable string, plus a row in `docs/DETECTION_CATALOG.md`
- [ ] Unit tests against fixtures in `integrity-testing/fixtures/`
- [ ] Instrumented test: one positive condition, one clean condition
- [ ] Implemented at the layer that is hardest to hook for its value (native where a JVM
      implementation would be trivially defeated)
- [ ] Failure degrades to `INCONCLUSIVE`, never silently to "clean"
- [ ] Default weight is conservative (new signals ship `INFORMATIONAL`)

### False-positive analysis

<!-- Required. Name at least one legitimate configuration that could trigger this signal,
     and explain why the default weight is safe. "None" is not an acceptable answer. -->

### Known bypass

<!-- Required. How would you defeat this check if you wanted to? -->

## Checks

- [ ] No new runtime dependency in `integrity-core`
- [ ] No restricted API usage (`docs/PRIVACY_AND_COMPLIANCE.md` §1) and no PII in evidence
- [ ] No main-thread IO; per-detector budget respected; cancellation-aware
- [ ] `./gradlew build detekt ktlintCheck apiCheck` passes locally
