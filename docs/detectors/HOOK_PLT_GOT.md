# Design: `HOOK_PLT_GOT`

**Status: design only. No implementation exists, and none should be written until this
document has been reviewed** — in particular §5 and §4, which between them decide whether
this detector is worth building. Writing the bypasses first is what capped
`HOOK_SELF_TEXT_MISMATCH` at a permanent ceiling rather than a hopeful one, and that
conclusion would have been much harder to reach with code already written.

---

## 0. Why this signal, and why now

Not because it is the next row in the catalog. Because it covers the **largest documented
blind spot of the detector we just shipped**.

`HOOK_SELF_TEXT_MISMATCH` compares executing code against the file it came from. Bypass 3
in its design is redirection through the GOT or an ART entry point, which changes **no
executable byte at all** — so that detector sees nothing, by construction, and no amount of
strengthening it will help.

```
call open()
   │
   ├── inline hook   → .text modified   → HOOK_SELF_TEXT_MISMATCH sees it
   └── GOT rewrite   → .text untouched  → nothing sees it today
```

Adding a third detector of the first kind would restate what the family already claims.
This one changes what it can claim.

## 1. Threat hypothesis

> An attacker redirects this library's calls to imported functions by overwriting entries in
> its Global Offset Table, so that `open`, `pread`, `read` or `dlopen` reach the attacker's
> code. No instruction in our `.text` changes.

This is not exotic: it is the cheapest way to defeat the detector we merged in PR #13, and
it is precisely how one would feed that detector the original bytes.

## 2. Detection mechanism

For this library's own module:

```
dl_iterate_phdr / PT_DYNAMIC
      ↓  locate DT_PLTGOT, DT_JMPREL, DT_PLTRELSZ, DT_SYMTAB, DT_STRTAB
enumerate GOT entries for imported functions
      ↓  for each target pointer
classify against /proc/self/maps  (the parser from PR #12, which already
      ↓                            reports permissions, offset and path)
      ├── file-backed and executable  → expected
      ├── executable but anonymous    → evidence
      ├── mapped but not executable   → evidence
      └── not mapped at all           → evidence
```

**The strongest single property is the anonymous one.** A legitimately resolved import
points into a file-backed executable mapping — some `.so` on disk. Injected trampolines
characteristically live in anonymous `r-xp` pages, because that is what an allocator hands
out. "Points into anonymous executable memory" is therefore a much sharper test than
"points somewhere plausible", and it needs no symbol resolution to evaluate.

**Evidence emitted** — counts and a classification, no paths, no symbol names (a symbol name
is not PII, but it narrows what an attacker learns from a leaked report for no analytic
gain):

| Key | Value |
|---|---|
| `entriesInspected` | how many GOT entries were classified |
| `anonymousExecutable` | count pointing into anonymous RX memory |
| `notExecutable` | count pointing into non-executable memory |
| `unmapped` | count pointing nowhere |

## 3. The question that comes before all of this: RELRO

**This must be measured before anything is designed further, because it may change the
threat model or remove it.**

`integrity-native/src/main/cpp/CMakeLists.txt` sets no RELRO flags, so whatever the NDK
toolchain defaults to is what ships. Recent NDKs default to full RELRO with `BIND_NOW`
(`-Wl,-z,relro,-z,now`), which resolves every import at load and then **maps the GOT
read-only**.

If that is what we ship:

- overwriting a GOT entry first requires an `mprotect`, which is a louder, rarer act than
  writing to an already-writable page;
- there is a **cheaper and sharper signal available**: the GOT should be inside a read-only
  mapping, and finding it writable is itself evidence, at a fraction of the ELF parsing;
- the `.got.plt` section, the usual target, may not exist as a writable region at all.

If we do **not** ship full RELRO, that is a finding in its own right and the fix is a link
flag, not a detector.

Either answer changes what gets built. Measuring it is one `readelf -d` and `readelf -l`
against the release `.so` in CI, and it should be the whole of the next PR.

## 4. Fixtures

**Clean.** Every GOT entry of our own module resolves into a file-backed executable
mapping, on both emulator images. Zero anonymous, zero non-executable, zero unmapped.

**Positive.** Same split as PR #13, for the same reason and with the same honesty cost.

- *Host:* the test overwrites one of its own GOT entries for real — the GOT is writable
  there or can be made so — points it at a scratch anonymous RX page, verifies the write
  landed, and requires the classifier to flag it. Genuine redirection of a real process.
- *Device:* the classifier is exercised through the existing read-only
  `measureSelfTextFrom`-style seam: a synthetic mapping table describing an anonymous
  executable region, and a pointer inside it. This tests classification against Android's
  real `/proc` parsing without shipping a write-my-own-GOT primitive.

The alternative — an on-device native entry point that writes the GOT — is worse than the
one rejected in PR #13, because the GOT is precisely what an attacker wants to write.

## 5. Known bypass — written before implementation

1. **Point into a file-backed executable module.** Overwrite the entry to target an address
   inside some legitimately mapped `.so` — including an agent library the attacker loaded
   normally, which *is* file-backed. Classification alone cannot distinguish this.
   *Cheap, and it defeats the primary property.*
2. **Hook the reading path.** We resolve the GOT by reading our own memory; an attacker who
   controls that read supplies the original pointers. *Cheap — and note this is the same
   bypass as PR #13's, so the two detectors share a single point of failure.*
3. **Restore on read.** Unhook while introspection runs. *Cheap.*
4. **Redirect a different module's GOT.** Hooking libc's own imports achieves most goals
   without touching ours. *Cheap.*
5. **Use inline hooking instead.** Covered by `HOOK_SELF_TEXT_MISMATCH` — this is the
   complementarity working as intended, and worth stating plainly: **the pair raises the
   cost of a silent hook; neither closes it.**
6. **Patch the classifier.** General to every in-process check.

Bypass 1 is the important one, and it is why this cannot be `CONFIRMED`. Bypass 2 is worth
naming loudly: two detectors that both die to one hooked `pread` are less independent than
their count suggests.

## 6. Expected `INCONCLUSIVE` cases

Distinguishable, per the rule in `CONTRIBUTING.md`:

| Condition | `reason` |
|---|---|
| No `PT_DYNAMIC` reachable | `no_dynamic_section` |
| `DT_PLTGOT` / `DT_JMPREL` absent | `no_got` |
| `/proc/self/maps` unreadable | `maps_unreadable` |
| Our own memory unreadable | `memory_unreadable` |
| Zero entries enumerated | `no_entries` |

`no_entries` is a failure, never a clean result — see §7.

## 7. Anti-vacuity conditions

1. **`entriesInspected > 0`, and above a floor.** "Some entries" is satisfied by one. The
   count should be compared against an independently obtained number — the same trick as
   the mapping count in PR #12, where the measurement's own walk was checked against a
   separate one.
2. **The classifier must be shown to flag.** A classifier that returns "expected" for every
   pointer produces a perfect clean result. Both directions, in the same run.
3. **The clean run must be non-trivial.** If a real module yields three GOT entries, this
   detector inspects almost nothing and should say so rather than reporting success.

## 8. Mutation entries the suite must catch

| Mutation | Caught by |
|---|---|
| classifier always returns "expected" | the positive fixture |
| classifier always returns "anonymous" | the clean fixture |
| anonymous check inverted | both |
| entry enumeration stops after one | the entry-count floor |
| `entriesInspected` reported without enumerating | the independent count |
| GOT bounds off by one | ASan, as in `maps.cpp` |

## 9. What this signal does **not** prove

- Not that the process is hooked. A GOT entry pointing somewhere unexpected is evidence of
  redirection, and legitimate instrumentation exists.
- **Its absence proves nothing.** Bypass 1 leaves it silent while the redirection stands.
- Nothing about other modules; only our own GOT is inspected.
- Nothing about inline hooks — that is the other detector, and neither covers the other's
  blind spot completely.
- It is not an anti-Frida check and has no knowledge of Frida.

## 10. Initial policy

- `POSSIBLE`, `INFORMATIONAL`, shadow mode.
- **The same permanent ceiling as `HOOK_SELF_TEXT_MISMATCH`, and for a sharper reason:**
  bypass 2 is shared between them. Two signals that fail to one hooked `pread` must not be
  allowed to combine into confidence that neither earns. Whether the risk scorer should
  treat them as correlated rather than independent is an open question for
  `docs/RISK_SCORING.md`, and it should be answered before either is promoted.

---

## Proposed sequence

Mirroring what worked for the last detector, and for the same reason: the cheap step that
can kill the design comes first.

```
#14  design (this document)
  ↓
#15  RELRO and GOT-shape measurement on the release .so and both images
       ├── full RELRO      → redesign around "the GOT should be read-only"
       ├── no RELRO        → fix the link flags first; that is the real finding
       └── writable GOT    → proceed as designed
  ↓
#16  implementation, with the fixtures, bypasses and mutations above
```

## Open questions for review

1. **Is the anonymous-executable property enough on its own**, or is symbol-to-module
   resolution worth the substantial extra ELF parsing? My view: start with anonymous-only.
   It is the sharp end, it needs no symbol table, and bypass 1 limits what the fuller
   version would buy.
2. **Should the shared bypass 2 change the scoring model** before either hook signal is
   promoted, rather than after?
3. **Is `#15` worth a whole PR?** It is smaller than PR #12 was — largely a CI assertion on
   the release `.so` — but it is the step that decides whether §2 or §3 is the real design.
