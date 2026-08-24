# 0001. Evidence-based API instead of boolean checks

Date: 2026-08-24
Status: Accepted

## Context

The obvious API for this SDK is `isRooted(): Boolean`, `isFridaPresent(): Boolean`. It is what
integrators ask for. It is also:

- a single, trivially patched branch — the entire bypass is one instruction;
- lossy — "found `su`" and "Play Integrity says the bootloader is unlocked" become the same
  value, so the host cannot weigh them;
- unfalsifiable — a `false` may mean "clean" or "the check could not run";
- a product decision made by the SDK, which has no idea whether the host is a bank or a
  to-do list.

## Decision

The SDK emits `Signal` objects (stable id, category, confidence, bounded evidence). A
separate, configurable scoring layer turns signals into a score and a `Verdict`. Coverage is
reported alongside the score. Hosts and backends may re-score the raw signals themselves.

## Consequences

- **Easier:** tuning without an SDK release; per-integrator policy; server-side re-scoring;
  honest handling of "could not determine" via `INCONCLUSIVE`.
- **Harder:** the API takes longer to learn than a boolean; documentation burden is higher;
  integrators must be steered away from `report.signals.isNotEmpty()`-style misuse.
- **Accepted:** we ship convenience helpers (`Policy.balanced()`, a response cookbook) rather
  than a boolean, and we call out the anti-pattern explicitly in the integration guide.
