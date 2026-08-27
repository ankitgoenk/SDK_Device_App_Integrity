# Risk Scoring & Policy

## Why scoring, not booleans

`isRooted() == true` is a bad API: it forces the SDK to make a product decision it has no
context for, and it collapses "found a `su` binary" and "Play Integrity says the bootloader
is unlocked" into the same thing. The SDK therefore emits evidence, scores it under a
configurable policy, and lets the host decide.

## Model

```
Signal(id, category, confidence, evidence)
        │
        ▼   per category: root, hooking, appTamper, environment, emulation, attestation, meta
categoryScore = min(100, Σ over signals ( weight(id).points × multiplier(confidence) ))
        │
        ▼   noisy-OR across categories, each damped by its policy factor
riskScore = round( 100 × ( 1 − Π over categories ( 1 − factor(c) × categoryScore(c)/100 ) ) )
        │
        ▼   thresholds, then escalation floors
Verdict ∈ { NO_EVIDENCE_OF_COMPROMISE, LOW_RISK, SUSPICIOUS, COMPROMISED, UNKNOWN }
```

**Why noisy-OR rather than an average.** Averaging across categories dilutes real evidence
with the categories that found nothing: a device with conclusive root evidence and nothing
else would score 100/6 ≈ 17 and read as clean. Noisy-OR is monotonic and saturating instead —
one category at 100 gives 100, and two independent categories at 40 give 64. That last number
matters: it is why "two corroborating categories beat any single heuristic" falls out of the
arithmetic rather than needing a special case.

### The word "independent" is doing real work there

Noisy-OR earns its corroboration property from independence, and nothing in the arithmetic
checks that the inputs actually have it. Two signals that fail to the *same* cause are one
signal wearing two hats, and combining them manufactures confidence that neither earned.

This is not hypothetical. `HOOK_SELF_TEXT_MISMATCH` and the proposed `HOOK_PLT_GOT` both
establish their evidence by reading this process's own memory through `pread`. An attacker
who hooks `pread` — the cheapest bypass in either design — feeds both of them the original
bytes at once:

```
                  ┌── HOOK_SELF_TEXT_MISMATCH ──┐
hooked pread ─────┤                             ├──► both silent, together
                  └── HOOK_PLT_GOT ─────────────┘
```

They are one **correlated evidence family**, not two votes. So:

- **Before promoting any signal above `INFORMATIONAL`, name what it shares with the signals
  already promoted** — the primitive it reads through, the file it trusts, the kernel
  interface it depends on. Independence is a claim about failure modes, not about how
  different two techniques look on paper.
- Where a shared failure mode exists, the family should contribute as one input, not as
  several. The current model has no way to express that, and it does not need one while
  every hook signal is `INFORMATIONAL` and contributing zero. **It needs one before the
  first promotion**, and discovering that afterwards would mean discovering it from a score
  that was already wrong.
- Two detectors sharing a bypass is still worth having: it raises the cost of a *silent*
  hook, because the attacker must cover both shapes. What it does not do is raise
  confidence when both stay quiet.

### Confidence multiplier

| Confidence | Multiplier | Meaning |
| --- | --- | --- |
| `CONFIRMED` | 1.0 | Direct, hard-to-fake observation (e.g. `TracerPid != 0`) |
| `LIKELY` | 0.7 | Strong heuristic with a plausible benign explanation |
| `POSSIBLE` | 0.4 | Weak or contextual heuristic |
| `INCONCLUSIVE` | 0.0 | Check could not run — contributes to `coverage`, not to score |

### Default weights

`H`=25, `M`=12, `L`=5, `I`=0, as tabled per signal in
[DETECTION_CATALOG.md](DETECTION_CATALOG.md). A category saturates at 100 so a single
category cannot be inflated by piling on correlated low-value signals.

### Escalation rules (override the weighted average)

These express "some things are decisive regardless of the arithmetic".

**A stronger layer is not a stronger mandate.** A native or attestation-backed check is
better evidence than a JVM one — harder to hook, harder to spoof. It is not thereby
entitled to block anyone. Every detection signal ships `INFORMATIONAL` whichever layer
produced it, and promotion comes from shadow-mode data, not from the implementation being
clever. Confusing evidential strength with enforcement authority is how integrity SDKs end
up locking out real users.

**An escalation never outranks the weight.** A signal still shipping at `INFORMATIONAL`
cannot fire an escalation, even when an escalation rule names it. Without that gate,
hard rule 6 — new signals ship `INFORMATIONAL` until shadow-mode data justifies promotion —
would be a fiction for any signal a rule happens to mention: it could force `COMPROMISED`
before anyone had seen its false-positive rate. Promoting the weight (for example
`AppDetectors.proposedWeights(policy)`) is what arms the escalation.

| Rule | Effect |
| --- | --- |
| Any `CONFIRMED` signal in `hooking` | `verdict ≥ COMPROMISED` |
| `APP_SIGNATURE_MISMATCH` or `APP_DEX_DIGEST_MISMATCH` `CONFIRMED` | `verdict = COMPROMISED` |
| `ATT_APP_NOT_RECOGNISED` (server) | `verdict = COMPROMISED` |
| `META_NATIVE_UNAVAILABLE` | `verdict ≥ SUSPICIOUS`, score floor 50 |
| ≥ 2 categories scoring ≥ 40 | `verdict ≥ SUSPICIOUS` (correlated evidence beats any single heuristic) |
| Coverage < 50% (many `INCONCLUSIVE`) | `verdict = UNKNOWN`, never the bottom rung |

### Verdict thresholds (default `Policy.balanced()`)

| Score | Verdict |
| --- | --- |
| 0–14 | `NO_EVIDENCE_OF_COMPROMISE` |
| 15–39 | `LOW_RISK` |
| 40–74 | `SUSPICIOUS` |
| 75–100 | `COMPROMISED` |
| n/a | `UNKNOWN` — insufficient coverage or not initialised |

## Coverage

`report.coverage` = fraction of enabled, applicable detectors that returned a conclusive
result. It is reported separately from the score and is the answer to "is a clean report
meaningful?" A `NO_EVIDENCE_OF_COMPROMISE` verdict at 35% coverage means almost nothing
ran, and a backend should treat it as `UNKNOWN`.

## Built-in policies

| Policy | Intended for | Character |
| --- | --- | --- |
| `Policy.observability()` | Rollout / shadow mode | All signals enabled, all weights recorded, **verdict always advisory**; nothing escalates |
| `Policy.balanced()` | Most apps | The defaults above |
| `Policy.strict()` | Banking, wallets, high-value payments | Higher weights for `environment`, `ENV_ACCESSIBILITY_SERVICE` and `ENV_OVERLAY_DETECTED` promoted, `UNKNOWN` treated as risk |
| `Policy.gaming()` | Anti-cheat | `ENV_MEMORY_EDITOR`, `VIRT_*`, `EMU_*` weighted up; `ENV_USER_CA_INSTALLED` down |

Policies are data, not code:

```kotlin
val policy = Policy.balanced()
    .withWeight(SignalId.ENV_ADB_ENABLED, Weight.INFORMATIONAL)
    .withDisabled(SignalId.ROOT_SU_EXEC)
    .withThresholds(suspicious = 35, compromised = 70)
```

`Policy` serialises to/from JSON so the **host** can fetch tuned weights from its own config
service and apply them at init — no SDK release needed to defuse a misbehaving signal.
(The SDK itself performs no network IO; the host supplies the JSON.)

## False-positive discipline

1. **Ship in shadow mode.** Every new integration runs `Policy.observability()` for at
   least one full release cycle. Enforce only once the score distribution is understood.
2. **Watch the distribution, not the examples.** Target: < 0.5% of legitimate sessions at
   `SUSPICIOUS` or above for a consumer app. If a signal fires on > 2% of sessions, it is
   either informational or broken.
3. **Never enforce on a single high-FP signal.** `ENV_VPN_ACTIVE`, `ENV_USER_CA_INSTALLED`,
   `ENV_ADB_ENABLED`, `APP_INSTALLER_UNEXPECTED` and `ENV_ACCESSIBILITY_SERVICE` must only
   contribute in combination.
4. **Accessibility is a special case.** Users of screen readers must never be blocked. Prefer
   Play Integrity's `appAccessRiskVerdict`, or match a curated list of known RAT packages,
   over "any non-allow-listed accessibility service".
5. **Per-signal kill switch.** Every signal can be disabled by policy at runtime by the host,
   so a bad detector is a config change, not an incident.
6. **Region and OEM awareness.** Track FP rates per `Build.MANUFACTURER` and locale; some
   ROM families need their own allowlists.

## Response cookbook (host side)

The SDK never blocks, never crashes, and never shows UI. Suggested host responses:

| Verdict | Consumer app | High-value action (payment, KYC, withdrawal) |
| --- | --- | --- |
| `NO_EVIDENCE_OF_COMPROMISE` | Proceed | Proceed |
| `LOW_RISK` | Proceed, log | Proceed, log |
| `SUSPICIOUS` | Proceed; flag server-side; raise limits scrutiny | Step-up auth; delay; server-side review |
| `COMPROMISED` | Degrade quietly (disable sensitive features), flag server-side | Refuse server-side, with a generic message |
| `UNKNOWN` | Proceed; retry evaluation later | Treat as `SUSPICIOUS` |

**Decide server-side wherever it matters.** The client can be patched to report anything,
and no rung of this enum is a grant of trust — ADR-0009 removed the name `TRUSTED` precisely
so that the table above cannot be misread as an authorisation policy. It is a suggestion for
*local* degradation; the decision that matters is the server's. See
[SERVER_VERIFICATION.md](SERVER_VERIFICATION.md).

**Do not react at the point of detection.** Immediately closing the app when a check fires
hands the attacker a breakpoint. Report, let the backend decide, and degrade later and
elsewhere ([ANTI_TAMPER.md](ANTI_TAMPER.md#5-decouple-detection-from-response)).
