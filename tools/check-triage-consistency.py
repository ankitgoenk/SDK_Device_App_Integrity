#!/usr/bin/env python3
"""Assert docs/DETECTION_TRIAGE.md still describes the code that exists.

`check-signal-catalog.py` checks the *catalogue* against production code. Nothing checked the
*triage*, and it drifted within hours: `APP_DEX_DIGEST_MISMATCH` shipped in one PR and the
triage still called it "BUILD (blocked)" on a dependency that had already landed. A verdict
document nobody verifies is a verdict document that is wrong, and this one is read as the
answer to "what should we build next".

Four things are checked, all mechanical:

  1. BUILT <-> shipped. Every triage row marked **BUILT** names a SignalId that SDK detector
     code emits, and every SignalId that SDK code emits has a row marked **BUILT**.

  2. The census adds up. Each family column in the "Standing count" table sums to the family
     size in its own header, and the Total column sums to the stated total.

  3. Each header equals the catalogue. The table advertises that each column sums to "the
     family's *catalogue* size" -- but check 2 only compares the table against itself, and
     both numbers are typed by the same hand in the same commit. So the declared size is now
     derived from DETECTION_CATALOG.md and compared against it. `HOOK_MAPS_INCONSISTENT` was
     triaged with no catalogue row at all: 21 HOOK rows sat under a header reading `HOOK (20)`,
     the DOCUMENT cell was written one short to match, and checks 1 and 2 both passed.

  4. Every triaged id is catalogued. The other direction of the same defect, caught directly
     rather than inferred from an arithmetic gap.

A catalogue family absent from the census must be named in UNCENSUSED with a reason, so leaving
one out is a decision somebody wrote down rather than a hole in the table.

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
CATALOG = ROOT / "docs" / "DETECTION_CATALOG.md"

SIGNAL_CTOR = re.compile(r'SignalId\(\s*"([A-Z][A-Z0-9_]+)"\s*\)')
ID_IN_CELL = re.compile(r"`([A-Z][A-Z0-9_]{3,})`")
CENSUS_HEADER = re.compile(r"\|\s*\|(.+)\|\s*$")
CENSUS_ROW = re.compile(r"^\|\s*(BUILT|BUILD|DEFER|DOCUMENT|DUPLICATE|DECLINE)\s*\|(.+)\|\s*$")
# `[A-Za-z]` deliberately: the last column is "Total (73)", and an all-caps pattern
# silently dropped it — which made META the grand total and produced a confident,
# wrong failure. The self-test below would not have caught that; running the gate did.
VERDICT_CELL = re.compile(r"^\*\*(BUILT|BUILD|DEFER|DOCUMENT|DUPLICATE|DECLINE)\*\*")
CATALOG_ID = re.compile(r"^\|\s*`([A-Z][A-Z0-9_]+)`")
FAMILY_SIZE = re.compile(r"([A-Za-z]+)\s*\((\d+)\)")

# META_* describe the SDK's own state rather than a device technique, so the triage records them
# in a producer table rather than giving them verdict rows. ATT_* and SRV_* are server-side
# vocabulary emitted by sample-backend, not by any detector; ADR-0008 keeps them out of scope.
EXEMPT_PREFIXES = ("META_", "ATT_", "SRV_")

# Catalogue families the census deliberately omits, and why. EMU/VIRT are untriaged for want of
# hardware and the triage says so in prose; SRV is produced by sample-backend while verifying a
# submission, so no device technique or rig applies to it. Anything not listed here must appear in
# the census -- which is what stops a family being dropped rather than decided about.
UNCENSUSED = {
    "EMU": "untriaged: no emulator rig (see the procurement list)",
    "VIRT": "untriaged: no cloned-container rig (see the procurement list)",
    "SRV": "server-side, emitted by sample-backend rather than any detector",
}

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


def catalog_ids(text: str) -> set[str]:
    """Every SignalId with a row in the catalogue."""
    return {m.group(1) for line in text.splitlines() if (m := CATALOG_ID.match(line))}


def catalog_families(text: str) -> dict[str, int]:
    """How many catalogue rows each family has, keyed by the id prefix (ROOT, HOOK, ...)."""
    counts: dict[str, int] = {}
    for signal in catalog_ids(text):
        counts[signal.split("_", 1)[0]] = counts.get(signal.split("_", 1)[0], 0) + 1
    return counts


def triaged_ids(text: str) -> set[str]:
    """Ids on any row whose second cell is a verdict, honouring grouped rows.

    Deliberately keyed on the verdict cell rather than on "looks like an id": the reference-stack
    table, the procurement list and the META producer table all carry backticked names in their
    first column and none of them is a verdict row.
    """
    found: set[str] = set()
    for line in text.splitlines():
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 2 or not VERDICT_CELL.match(cells[1]):
            continue
        found |= set(ID_IN_CELL.findall(cells[0]))
    return found


def check(root: pathlib.Path, text: str, catalog: str) -> list[str]:
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

    catalogued = catalog_ids(catalog)
    if not catalogued:
        return ["parsed zero rows from docs/DETECTION_CATALOG.md — the parser is broken"]

    # Check 4. A triaged id with no catalogue row is invisible to check 1 (it is never in code)
    # and to check 2 (the census is only compared against itself).
    for signal in sorted(triaged_ids(text) - catalogued):
        problems.append(
            f"`{signal}` has a triage verdict but no row in docs/DETECTION_CATALOG.md "
            f"(the catalogue is where a re-proposal gets checked; add the row)"
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
    # Check 3. The declared size is derived from the catalogue rather than trusted.
    sizes = catalog_families(catalog)
    censused = {name for name, _ in families[:-1]}
    for name, declared in families[:-1]:
        actual = sizes.get(name)
        if actual is None:
            problems.append(f"census column {name} names a family with no catalogue rows")
        elif actual != declared:
            problems.append(
                f"census header declares {name} ({declared}), but the catalogue has "
                f"{actual} `{name}_*` row(s)"
            )

    # Check 5. A family may be left out of the census, but only on purpose.
    for name in sorted(set(sizes) - censused - set(UNCENSUSED)):
        problems.append(
            f"catalogue family {name} ({sizes[name]} row(s)) is in neither the census nor "
            f"UNCENSUSED — add a column, or record why it has none"
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
    catalog = CATALOG.read_text(encoding="utf-8")
    if check(ROOT, text, catalog):
        print("SELF-TEST ABORT: the real triage does not pass, so a mutant proves nothing.",
              file=sys.stderr)
        return 1

    # A catalogue row for a family the census does not cover, and one that inflates a family
    # the census does cover. Neither is reachable by editing the triage alone, which is why
    # check() takes the catalogue as an argument rather than reading it.
    extra_root = "| `ROOT_NOT_A_REAL_SIGNAL` | t | NAT | H | low | b |\n"
    extra_new_family = "| `XYZ_NOT_A_REAL_FAMILY` | t | NAT | H | low | b |\n"
    drop_triaged = "| `HOOK_MAPS_INCONSISTENT` |"

    cases = [
        ("a BUILT row demoted to BUILD",
         text.replace("| `ROOT_PROP_SPOOF` | **BUILT**", "| `ROOT_PROP_SPOOF` | **BUILD**", 1),
         catalog),
        ("a BUILT row for a signal nothing emits",
         text.replace("| `ROOT_PROP_SPOOF` | **BUILT**", "| `ROOT_NOT_A_REAL_SIGNAL` | **BUILT**", 1),
         catalog),
        ("a census cell miscounted", _bump_census(text, column=0), catalog),
        ("a census total that does not match its column", _bump_census(text, column=-1), catalog),
        # Check 4: the HOOK_MAPS_INCONSISTENT regression, reproduced directly.
        ("a triaged id whose catalogue row was removed",
         text,
         "\n".join(l for l in catalog.splitlines() if not l.startswith(drop_triaged)) + "\n"),
        # Check 3, isolated: the census still sums to its own header, and the header is now wrong.
        ("a census header that no longer matches the catalogue",
         text,
         catalog.replace("| `ROOT_SU_BINARY` |", extra_root + "| `ROOT_SU_BINARY` |", 1)),
        # Check 5: a family in the catalogue that the census neither covers nor exempts.
        ("a catalogue family in neither the census nor UNCENSUSED",
         text,
         catalog.replace("| `ROOT_SU_BINARY` |", extra_new_family + "| `ROOT_SU_BINARY` |", 1)),
    ]

    failures = 0
    for label, mutated, mutated_catalog in cases:
        if mutated == text and mutated_catalog == catalog:
            print(f"  NOT APPLIED: {label} — the mutation text no longer matches the document",
                  file=sys.stderr)
            failures += 1
            continue
        if not check(ROOT, mutated, mutated_catalog):
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

    problems = check(ROOT, TRIAGE.read_text(encoding="utf-8"), CATALOG.read_text(encoding="utf-8"))
    if problems:
        print("FAIL: docs/DETECTION_TRIAGE.md no longer describes the code.\n", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        print("\nThe triage is read as the answer to \"what should we build next\". "
              "A stale verdict sends someone to build something that already exists.",
              file=sys.stderr)
        return 1

    text = TRIAGE.read_text(encoding="utf-8")
    built = built_rows(text)
    triaged = len(triaged_ids(text))
    catalogued = len(catalog_ids(CATALOG.read_text(encoding="utf-8")))
    print(
        f"OK: {len(built)} BUILT verdict(s) match the SDK's emitted signals; "
        f"{triaged} triaged id(s), all catalogued; census matches the catalogue "
        f"({catalogued} row(s) total)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
