# Risk Scoring & Policy

## Why scoring, not booleans

`isRooted() == true` is a bad API: it forces the SDK to make a product decision it has no
context for, and it collapses "found a `su` binary" and "Play Integrity says the bootloader
is unlocked" into the same thing. The SDK therefore emits evidence, scores it under a
configurable policy, and lets the host decide.

## Model

```
Signal(id, category, confidence, weight?, evidence)
        │
        ▼   per category: root, hooking, appTamper, environment, emulation, attestation
CategoryScore = min(100, cap(Σ w_i · c_i) )
        │
        ▼
riskScore = min(100, Σ over categories ( categoryScore · categoryFactor ) / Σ factors  … with escalation rules)
        │
        ▼
Verdict ∈ { TRUSTED, LOW_RISK, SUSPICIOUS, COMPROMISED, UNKNOWN }
```

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

These express "some things are decisive regardless of the arithmetic":

| Rule | Effect |
| --- | --- |
| Any `CONFIRMED` signal in `hooking` | `verdict ≥ COMPROMISED` |
| `APP_SIGNATURE_MISMATCH` or `APP_DEX_DIGEST_MISMATCH` `CONFIRMED` | `verdict = COMPROMISED` |
| `ATT_APP_NOT_RECOGNISED` (server) | `verdict = COMPROMISED` |
| `META_NATIVE_UNAVAILABLE` | `verdict ≥ SUSPICIOUS`, score floor 50 |
| ≥ 2 categories scoring ≥ 40 | `verdict ≥ SUSPICIOUS` (correlated evidence beats any single heuristic) |
| Coverage < 50% (many `INCONCLUSIVE`) | `verdict = UNKNOWN`, never `TRUSTED` |

### Verdict thresholds (default `Policy.balanced()`)

| Score | Verdict |
| --- | --- |
| 0–14 | `TRUSTED` |
| 15–39 | `LOW_RISK` |
| 40–74 | `SUSPICIOUS` |
| 75–100 | `COMPROMISED` |
| n/a | `UNKNOWN` — insufficient coverage or not initialised |

## Coverage

`report.coverage` = fraction of enabled, applicable detectors that returned a conclusive
result. It is reported separately from the score and is the answer to "is a clean report
meaningful?" A `TRUSTED` verdict with 35% coverage should be treated by a backend as
`UNKNOWN`.

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
| `TRUSTED` | Proceed | Proceed |
| `LOW_RISK` | Proceed, log | Proceed, log |
| `SUSPICIOUS` | Proceed; flag server-side; raise limits scrutiny | Step-up auth; delay; server-side review |
| `COMPROMISED` | Degrade quietly (disable sensitive features), flag server-side | Refuse server-side, with a generic message |
| `UNKNOWN` | Proceed; retry evaluation later | Treat as `SUSPICIOUS` |

**Decide server-side wherever it matters.** The client can be patched to report `TRUSTED`;
the backend's copy of the decision cannot. See
[SERVER_VERIFICATION.md](SERVER_VERIFICATION.md).

**Do not react at the point of detection.** Immediately closing the app when a check fires
hands the attacker a breakpoint. Report, let the backend decide, and degrade later and
elsewhere ([ANTI_TAMPER.md](ANTI_TAMPER.md#5-decouple-detection-from-response)).
