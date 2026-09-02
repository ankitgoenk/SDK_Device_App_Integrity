# Fixtures

**This directory is empty, and that is the finding rather than the fix.**

Five documents describe it as populated — `TESTING.md` §1 calls fixtures "the backbone" of the
test strategy, `CONTRIBUTING.md`'s definition of done has a checkbox reading "Unit tests against
fixtures in `integrity-testing/fixtures/`", and `DETECTION_CATALOG.md`'s new-signal checklist
says "unit test the parsing logic against captured fixtures (real `/proc` dumps in
`integrity-testing`)". The path had never existed. Those documents now say so; this file records
what belongs here and why, so the first capture has somewhere to go and a shape to arrive in.

## Why this is not merely a missing folder

The captures were taken. They produced results recorded in this repository as measurements. They
are on somebody's laptop.

`TESTING.md` §9, on verifying the ashmem fix:

> **`K1` after the ashmem fix: verified by replay, not on the device.** The Pixel was unavailable
> when `/dev/ashmem/` was added to the exclusions, so the shipped predicate was replayed offline
> against the stored `K1` captures instead … re-run it on hardware when the Pixel is next
> attached.

A verification against data nobody else holds, whose conclusion is recorded as fact, that no one
can reproduce, with a follow-up gated on one person's physical access to one phone. The same
section sets the standard it erodes: "a table of assumptions formatted like evidence is worse
than no table."

And the bill has already been paid once, in that section's own words:

> (3471 lines; the distinct-path figure first published here was produced by the flawed extractor
> described below and **is withdrawn rather than restated, since that capture was not kept**)

A published measurement deleted rather than corrected, because the input was gone. Had it been
committed, the broken `awk` could have been re-run properly.

That `awk` is the second argument. It "took the last whitespace-separated field as the path, and
for these lines that field is `(deleted)`" — so it reported the right answer from a rule that
would not have produced it, and only a physical device caught the discrepancy. A committed
capture fed through `MapsParser` has no second implementation to disagree with. It is the same
hazard `DexAggregate` exists to remove, one layer out: an `awk` one-liner and `MapsParser` are
two implementations of `/proc/self/maps`.

The third is `Mapping.isFileBacked`'s own device table. `/dev/ashmem/jit-zygote-cache_4112_4112
(deleted)` appears on Android 11 and on neither newer reference phone. Nobody would hand-write
that into a test, because nobody knew it existed — which is exactly what a real capture is for,
and why the `clean-baseline` CI job now boots an API 30 emulator per commit to cover what a
50 KB text file would cover in milliseconds.

## What belongs here first

Named in `TESTING.md` §9, in descending order of value:

| File | Capture |
| --- | --- |
| `maps/k1-pixel10a-api36-clean.txt` | `K1`, no module scoped — the clean control |
| `maps/k2-pixel10a-api36-vector-scoped.txt` | `K2`, Vector scoped to `sample-app` — **the positive control**, the one mapping under `/data/adb/modules/zygisk_vector/` |
| `maps/c1-m2101k6i-api33-clean.txt` | `C1`, stock MIUI — where `/data/misc/apexdata/com.android.art/` appears and `K1` never shows it |
| `maps/m1-a50s-api30-magisk.txt` | `M1`, Android 11 — the `ashmem` JIT cache form |

## Rules for a capture

1. **Record provenance beside it.** Device, Android version, API level, rig state, capture date.
   A fixture without provenance is a mystery file in two years.

2. **Record how it was captured, and capture it from the app.** `TESTING.md` §9 is emphatic that
   `run-as` and `adb shell` results do not transfer: a `run-as` shell is not zygote-forked, so it
   does not inherit Zygisk injection or per-uid package filtering. "Package visibility, in-process
   state **and system properties** must all be re-measured from inside the app before being relied
   on." A shell-context capture looks identical to an app-context one and is wrong.

3. **Feed it through the production parser.** The value is not the file; it is that `MapsParser`,
   `Mapping.isFileBacked` and `EXPECTED_PREFIXES` run against real bytes. A test per fixture
   asserting the outcome §9 already reports — 0 signals clean, 1 `CONFIRMED` hooked, 0 on the
   second device — turns four prose claims into four assertions that re-run on every commit.

4. **Check it before committing.** A maps dump carries the app's own package paths and may carry
   others. For `sample-app` on the team's own rigs that is fine; anything from a personal device
   needs a look against privacy rules P3 and P5 first.

## Related, and also absent

`TESTING.md` §2 asks for rig setup scripts in `tools/rigs/`, "not as tribal knowledge on one
engineer's spare phone" — which is where `K1`, `K2` and `K4` currently live. The precedent for
doing better is already in the repository: `tools/xposed-buildspoof-fixture/` is `K4`'s positive
control, committed, and `DETECTION_TRIAGE.md` is rightly pleased that "it lives in this
repository". The instinct was applied to the rig and not to the captures.
