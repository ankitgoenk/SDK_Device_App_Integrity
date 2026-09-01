#!/usr/bin/env python3
"""Assert docs/DETECTION_TRIAGE.md still describes the code that exists.

`check-signal-catalog.py` checks the *catalogue* against production code. Nothing checked the
*triage*, and it drifted within hours: `APP_DEX_DIGEST_MISMATCH` shipped in one PR and the
triage still called it "BUILD (blocked)" on a dependency that had already landed. A verdict
document nobody verifies is a verdict document that is wrong, and this one is read as the
answer to "what should we build next".

Two things are checked, both mechanical:

  1. BUILT <-> shipped. Every triage row marked **BUILT** names a SignalId that SDK detector
     code emits, and every SignalId that SDK code emits has a row marked **BUILT**.

  2. The census adds up. Each family column in the "Standing count" table sums to the family
     size in its own header, and the Total column sums to the stated total. The table advertises
     this property ("so each column sums to the family's catalogue size and a miscount is
     visible") and until now the only thing making it visible was somebody adding it up by hand.

Deliberately out of scope: whether BUILD/DEFER/DOCUMENT verdicts are still *correct*. That is a
judgement about hardware and measurement, and a checker guessing at it would only teach people
to satisfy the checker.

Usage: tools/check-triage-consistency.py [--self-test]
"""
from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
TRIAGE = ROOT / "docs" / "DETECTION_TRIAGE.md"

SIGNAL_CTOR = re.compile(r'SignalId\(\s*"([A-Z][A-Z0-9_]+)"\s*\)')
ID_IN_CELL = re.compile(r"`([A-Z][A-Z0-9_]{3,})`")
CENSUS_HEADER = re.compile(r"\|\s*\|(.+)\|\s*$")
CENSUS_ROW = re.compile(r"^\|\s*(BUILT|BUILD|DEFER|DOCUMENT|DUPLICATE|DECLINE)\s*\|(.+)\|\s*$")
# `[A-Za-z]` deliberately: the last column is "Total (73)", and an all-caps pattern
# silently dropped it — which made META the grand total and produced a confident,
# wrong failure. The self-test below would not have caught that; running the gate did.
FAMILY_SIZE = re.compile(r"([A-Za-z]+)\s*\((\d+)\)")

# META_* describe the SDK's own state rather than a device technique, so the triage records them
# in a producer table rather than giving them verdict rows. ATT_* and SRV_* are server-side
# vocabulary emitted by sample-backend, not by any detector; ADR-0008 keeps them out of scope.
EXEMPT_PREFIXES = ("META_", "ATT_", "SRV_")

# Only the SDK's detector modules count as "shipped". sample-backend emits server-side ids that
# the triage deliberately does not cover.
SDK_GLOBS = ("integrity-*/src/main/**/*.kt",)


def shipped_ids(root: pathlib.Path) -> set[str]:
    found: set[str] = set()
    for glob in SDK_GLOBS:
        for path in root.glob(glob):
            if "/build/" in str(path):
                continue
            found |= set(SIGNAL_CTOR.findall(path.read_text(encoding="utf-8")))
    return {i for i in found if not i.startswith(EXEMPT_PREFIXES)}


def built_rows(text: str) -> set[str]:
    """Ids on a row whose verdict cell is **BUILT**, honouring grouped rows."""
    found: set[str] = set()
    for line in text.splitlines():
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 2 or not cells[1].startswith("**BUILT**"):
            continue
        # Grouped rows list several ids in one cell: `A`, `B`, `C` | **BUILD** | ...
        found |= set(ID_IN_CELL.findall(cells[0]))
    return {i for i in found if not i.startswith(EXEMPT_PREFIXES)}


def census(text: str) -> tuple[list[tuple[str, int]], dict[str, list[int]]]:
    """The family headers with their declared sizes, and each outcome row's numbers."""
    families: list[tuple[str, int]] = []
    rows: dict[str, list[int]] = {}
    for line in text.splitlines():
        if not families:
            header = CENSUS_HEADER.match(line)
            if header and "BUILT" not in line:
                pairs = FAMILY_SIZE.findall(header.group(1))
                if len(pairs) >= 3:
                    families = [(name, int(size)) for name, size in pairs]
            continue
        row = CENSUS_ROW.match(line)
        if row:
            cells = [c.strip() for c in row.group(2).split("|")]
            rows[row.group(1)] = [
                0 if c in ("—", "-", "") else int(re.sub(r"\D", "", c) or 0) for c in cells
            ]
    return families, rows


def check(root: pathlib.Path, text: str) -> list[str]:
    problems: list[str] = []

    shipped = shipped_ids(root)
    built = built_rows(text)

    # Vacuity guards. Either of these empty means the parser broke, not the docs — and a
    # checker that passes because it found nothing is the failure this repository keeps hitting.
    if not shipped:
        return ["parsed zero SignalIds from SDK code — the parser is broken, not the triage"]
    if not built:
        return ["parsed zero **BUILT** rows from the triage — the parser is broken, not the code"]

    for signal in sorted(shipped - built):
        problems.append(
            f"`{signal}` is emitted by SDK code but its triage row is not **BUILT** "
            f"(it shipped; say so, or stop shipping it)"
        )
    for signal in sorted(built - shipped):
        problems.append(
            f"`{signal}` is marked **BUILT** in the triage but no SDK detector emits it "
            f"(it was removed or renamed, or the row is aspirational)"
        )

    families, rows = census(text)
    if not families or not rows:
        problems.append("could not parse the Standing count table — the parser is broken")
        return problems

    for index, (name, declared) in enumerate(families[:-1]):
        total = sum(values[index] for values in rows.values() if index < len(values))
        if total != declared:
            problems.append(
                f"census column {name} sums to {total}, but its header declares {declared}"
            )
    grand_declared = families[-1][1]
    grand_total = sum(values[-1] for values in rows.values())
    if grand_total != grand_declared:
        problems.append(
            f"census Total column sums to {grand_total}, but the header declares {grand_declared}"
        )
    return problems


def _bump_census(text: str, column: int) -> str:
    """Add one to a cell of the first census row, derived from the document.

    Deliberately not a hardcoded string. The first version of this self-test pinned the literal
    row `| BUILT | 4 | — | 1 | 3 | — | 7 | **15** |`, so the very next legitimate census change
    turned two mutants into "NOT APPLIED" — which the runner reports as a failure rather than a
    pass, but a self-test that breaks whenever the thing it guards is edited will be deleted by
    the third person who hits it.
    """
    for line in text.splitlines():
        row = CENSUS_ROW.match(line)
        if not row:
            continue
        cells = [c.strip() for c in row.group(2).split("|")]
        index = column if column >= 0 else len(cells) - 1
        raw = cells[index]
        digits = re.sub(r"\D", "", raw)
        if not digits:
            continue
        bumped = raw.replace(digits, str(int(digits) + 1), 1)
        mutated_cells = list(cells)
        mutated_cells[index] = bumped
        mutated_line = f"| {row.group(1)} | " + " | ".join(mutated_cells) + " |"
        return text.replace(line, mutated_line, 1)
    return text  # no census row found; the runner reports this as NOT APPLIED


def self_test() -> int:
    """Prove the checker rejects the broken cases. Hard rule 10: a gate that cannot fail is
    worse than no gate, so every assertion above ships with a case that trips it."""
    text = TRIAGE.read_text(encoding="utf-8")
    if check(ROOT, text):
        print("SELF-TEST ABORT: the real triage does not pass, so a mutant proves nothing.",
              file=sys.stderr)
        return 1

    cases = [
        ("a BUILT row demoted to BUILD",
         text.replace("| `ROOT_PROP_SPOOF` | **BUILT**", "| `ROOT_PROP_SPOOF` | **BUILD**", 1)),
        ("a BUILT row for a signal nothing emits",
         text.replace("| `ROOT_PROP_SPOOF` | **BUILT**", "| `ROOT_NOT_A_REAL_SIGNAL` | **BUILT**", 1)),
        ("a census cell miscounted", _bump_census(text, column=0)),
        ("a census total that does not match its column", _bump_census(text, column=-1)),
    ]

    failures = 0
    for label, mutated in cases:
        if mutated == text:
            print(f"  NOT APPLIED: {label} — the mutation text no longer matches the document",
                  file=sys.stderr)
            failures += 1
            continue
        if not check(ROOT, mutated):
            print(f"  SURVIVED: {label}", file=sys.stderr)
            failures += 1
        else:
            print(f"  killed: {label}")

    if failures:
        print(f"\nSELF-TEST FAILED: {failures} case(s) the gate does not catch.", file=sys.stderr)
        return 1
    print(f"\nSELF-TEST OK: {len(cases)} deliberately broken triages, all rejected.")
    return 0


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()

    if not TRIAGE.exists():
        print(f"FAIL: {TRIAGE} is missing.", file=sys.stderr)
        return 1

    problems = check(ROOT, TRIAGE.read_text(encoding="utf-8"))
    if problems:
        print("FAIL: docs/DETECTION_TRIAGE.md no longer describes the code.\n", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        print("\nThe triage is read as the answer to \"what should we build next\". "
              "A stale verdict sends someone to build something that already exists.",
              file=sys.stderr)
        return 1

    built = built_rows(TRIAGE.read_text(encoding="utf-8"))
    print(f"OK: {len(built)} BUILT verdict(s) match the SDK's emitted signals; census adds up.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
