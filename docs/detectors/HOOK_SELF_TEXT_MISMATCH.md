# Design: `HOOK_SELF_TEXT_MISMATCH`

**Status: design only. No implementation exists, and none should be written until this
document has been reviewed.** The point of writing it first is that two of the sections
below — the known bypass and the positive fixture — decide whether the detector is worth
building at all, and both are much easier to argue away once code exists.

---

## 0. Why this signal first

The catalog lists twelve `HOOK_*` signals. This one is not the most powerful; it is the one
whose **positive fixture can be produced honestly**, which is the constraint that should
choose the first detector.

| Candidate | Why not first |
|---|---|
| `HOOK_FRIDA_MAPS` / `_THREADS` / `_PORT` | The evidence is a string or a port number. Renaming a file defeats it, and the positive fixture means running Frida inside CI. |
| `HOOK_INLINE_PROLOGUE` | The oracle is a table of expected instruction patterns per architecture. A weak oracle: it can only recognise the trampolines we thought of. |
| `HOOK_ART_METHOD_ANOMALY` | Needs per-ART-version knowledge. Correct eventually, wrong to start with. |
| **`HOOK_SELF_TEXT_MISMATCH`** | The oracle is **the file the code was loaded from** — ground truth, not a pattern list. And the positive fixture can be a real modification of a real process image. |

It also uses only capabilities already built and hardened: `/proc/self/maps` parsing and
`readSelfMemory`, both now at 22/22 mutation score.

---

## 1. Threat hypothesis

> An attacker has our library loaded in the host process and modifies its executable code
> **after load** — typically overwriting a function prologue with a branch to their own
> code, so that calls into our detection routines are diverted, weakened, or made to return
> a fixed answer.

This is the standard inline hook. It is what Frida's Interceptor, Xposed's native side, and
every hand-rolled ARM64 trampoline do to a function they want to control.

The attacker's goal is not to break the SDK loudly. It is to make it **report clean**.

## 2. Detection mechanism

For the executable mapping belonging to this SDK's own `libintegrity.so`:

```
/proc/self/maps
      ↓  parse (maps.cpp)
find the r-xp mapping whose path is our own .so
      ↓  readSelfMemory      → what is executing now
      ↓  read the same file offset from the .so on disk
compare
      ↓
differ → evidence
```

Both reads go through the hardened paths. Neither dereferences an address derived from
parsed input.

**Evidence emitted** (non-PII by construction — offsets within our own library, no paths,
no package names):

| Key | Value |
|---|---|
| `region` | `self_text` |
| `bytesCompared` | how many bytes were actually compared |
| `firstDifferingOffset` | offset within the mapping, or absent |
| `differingByteCount` | how many bytes differ |

## 3. Clean fixture — must produce **no** signal

- `google_apis_playstore`, `x86_64`, API 34 — the existing clean-baseline job.
- `google_apis`, `x86_64` — the rooted image. **A rooted device is not a hooked one**, and
  this detector must stay silent there. That distinction is the whole reason for separating
  the ROOT and HOOK categories.
- Both must also be silent when the SDK is loaded normally in `sample-app`.

**The false-positive risk that decides whether this ships: text relocations.** If any
relocation is applied into `.text` at load time, a perfectly clean process shows a
mismatch. Android shared libraries are built `-fPIC` and put relocated addresses in
`.data.rel.ro` and the GOT rather than `.text`, so this should not occur — but "should not"
is not evidence. **The first implementation step is to measure the clean mismatch count on
both images and confirm it is exactly zero.** If it is not, this detector does not ship in
this form, and that outcome is a legitimate result of the exercise rather than a failure.

## 4. Positive fixture — how a genuinely hooked process is produced

This is the section that decides whether the detector is testable, so it is stated plainly:

> **The test hooks itself, for real.** It calls `mprotect` on one page of our own
> `.text`, writes a branch instruction over a function prologue, and restores it afterwards.

That is not a mock and not a flag that says "pretend I'm hooked". It is the same
observable state an inline hook produces: **the bytes executing in memory no longer match
the bytes in the file they came from.** The detector is given no special knowledge that a
test is running.

What it is *not*: proof that this detector catches Frida, or Xposed, or any specific tool.
It establishes that the detector observes real post-load code modification. Claiming more
than that from this fixture would be the "beautiful test of a fake universe" in a slightly
better costume.

**If `mprotect` on our own text is refused** on some image (W^X policy), the fixture cannot
be built there and the test must say so — see §7 — rather than passing quietly.

## 5. Known bypass — written before implementation

A competent attacker defeats this check in at least six ways, and they are not equally hard:

1. **Hook the reading path instead.** We read through `pread` on `/proc/self/mem`. An
   attacker who hooks `pread`, `open`, or `openat` in libc can hand us the original bytes.
   *Cheap, and it defeats the check completely.*
2. **Restore on read.** Unhook while introspection is happening, re-hook afterwards.
   Established practice in hiding frameworks. *Cheap.*
3. **Do not touch `.text` at all.** Redirect through the GOT/PLT, or swap an ART method
   entry point. No executable byte changes. *Cheap, and completely invisible here — this is
   the largest blind spot.*
4. **Hook a different module.** Hooking `libc`'s `open` achieves most attacker goals without
   touching our library at all. *Cheap.*
5. **Modify the `.so` on disk before load.** Then memory and file agree, because both are
   the attacker's. *Moderate — needs to survive signature checking, which is a different
   signal's job (`APP_SIGNATURE_MISMATCH`, `APP_NATIVE_LIB_MISMATCH`).*
6. **Patch this detector.** Overwrite the comparison, or the branch that acts on its result.
   *Moderate, and it is the general problem with any in-process check.*

Bypasses 1–4 are cheap. **This signal is therefore evidence, never proof**, and its weight
must reflect that permanently, not just during shadow mode.

## 6. Expected `INCONCLUSIVE` cases

Every one of these is a legitimate "I could not check", and each must be distinguishable in
evidence rather than collapsing into a bare silence:

| Condition | `reason` |
|---|---|
| `/proc/self/maps` unreadable (SELinux, hardened ROM) | `maps_unreadable` |
| No mapping found for our own library | `self_mapping_not_found` |
| The `.so` file cannot be opened | `library_file_unreadable` |
| `readSelfMemory` returns `kStatusUnavailable` | `memory_unreadable` |
| The mapping is larger than the read budget | `region_too_large` |

Per hard rule 2 and `CONTRIBUTING.md`, none of these may produce an empty result implying
"clean".

## 7. Anti-vacuity conditions

Three, because this detector has three distinct ways to test nothing while passing:

1. **The patch must be proven applied.** Before asserting the detector fires, the test reads
   the patched byte back and confirms it differs from the original. If `mprotect` silently
   failed, the test must fail with "the fixture could not be built", not with "the detector
   did not fire".
2. **The comparison must be proven to have happened.** `bytesCompared` must be greater than
   zero in the clean case too. A detector that compares nothing agrees with everything.
3. **Both directions on the same image.** Clean → no signal, patched → signal, in the same
   test run. A detector that never fires passes any clean-only suite; a detector that always
   fires passes any positive-only suite.

## 8. Mutation tests the suite must catch

The detector ships with entries in `tools/mutate-native.py`. At minimum:

| Mutation | Must be caught by |
|---|---|
| comparison always reports "match" | the positive fixture |
| comparison always reports "differ" | the clean fixture |
| compares only the first byte | a patch applied later in the region |
| `bytesCompared` reported without comparing | the anti-vacuity assertion |
| a failed read reported as `kStatusOk` | the seam test, pointed at a missing file |
| region bounds off by one | ASan, as in `maps.cpp` |

## 9. What this signal does **not** prove

Stated here so it cannot be quietly upgraded later by someone reading only the signal name:

- It does **not** prove the process is hooked. It reports that in-memory code differs from
  the file it was loaded from. Legitimate runtime patching exists.
- Its **absence proves nothing at all.** Bypasses 1–4 leave it silent, and bypass 3 —
  GOT/PLT and ART entry-point redirection — is both cheap and entirely outside what this
  observes.
- It says nothing about **other libraries**. Only our own `.so` is inspected.
- It does **not** detect a tampered library on disk. Memory and file agreeing means only
  that they agree.
- It is **not** an anti-Frida check. It has no knowledge of Frida.

The wording that must appear in the catalog and in any host-facing documentation:

> **Evidence consistent with post-load code modification.** Not proof of hooking, and its
> absence is not evidence of a clean process.

## 10. Initial policy

- Ships at `INFORMATIONAL` (hard rule 6). Contributes **zero** to the risk score; the
  central `actionable` filter in `RiskScorer` enforces this structurally.
- Shadow mode only. Promotion requires field data on the clean-mismatch rate across real
  devices — the OEM variety this project has no access to yet.
- **Given bypasses 1–4, promotion above `SUSPICIOUS` weight should not be expected even
  with good field data.** A signal an attacker can silence for the price of one libc hook
  cannot carry enforcement alone.

---

## Open questions for review

1. **Scope of the compared region.** The whole `r-xp` mapping, or a bounded window around
   the entry points we care about? Whole-region is a stronger check and a larger read
   budget; `kMaxSafeReadBytes` is 64 KB and our `.so` is ~6.6 KB, so whole-region is
   currently affordable — but that stops being true as phase 3b grows the library.
2. **Is the disk read affordable off the main thread at `QUICK` depth**, or is this
   `FULL`-only? Leaning `FULL`.
3. **Does the clean mismatch count actually measure zero** on both CI images? If not, this
   design does not proceed.
