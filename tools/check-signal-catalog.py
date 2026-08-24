#!/usr/bin/env python3
"""Enforce the evidence chain every detection signal must carry.

A signal is only as trustworthy as what is known about it. For each SignalId that exists
in production code this checks:

  1. it has a row in docs/DETECTION_CATALOG.md               (Signal -> Evidence)
  2. that row states a false-positive risk                   (False-positive analysis)
  3. that row states the technique and a known bypass        (Known bypass)
  4. at least one unit test references it by name            (Unit test)

Expected result, evidence shape and "instrumented test where appropriate" stay with human
review: a checker that guessed at those would only teach people how to satisfy the checker.

META_* rows describe the SDK's own state rather than the device's, so they carry no
false-positive or bypass analysis — there is nothing about the user's device to get wrong.

Usage: tools/check-signal-catalog.py
"""
from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
CATALOG = ROOT / "docs" / "DETECTION_CATALOG.md"

CODE_ID = re.compile(r'SignalId\(\s*"([A-Z][A-Z0-9_]+)"\s*\)')
TABLE_ROW = re.compile(r"^\|(.+)\|\s*$", re.MULTILINE)

# Placeholder text that satisfies the letter of a column but not its purpose.
PLACEHOLDERS = {"", "-", "--", "tbd", "todo", "n/a", "na", "?", "tba", "none"}

# Ids that exist only to describe the scaffold itself.
EXEMPT: set[str] = set()


def is_placeholder(cell: str) -> bool:
    return cell.strip().strip("`*_").lower() in PLACEHOLDERS


def code_ids() -> set[str]:
    found: set[str] = set()
    for path in ROOT.rglob("*.kt"):
        parts = str(path)
        if "/build/" in parts or "/src/test/" in parts or "/src/androidTest/" in parts:
            continue
        found |= set(CODE_ID.findall(path.read_text(encoding="utf-8")))
    return found - EXEMPT


def test_ids() -> set[str]:
    found: set[str] = set()
    for path in ROOT.rglob("*.kt"):
        if "/src/test/" not in str(path):
            continue
        text = path.read_text(encoding="utf-8")
        found |= set(re.findall(r"\b([A-Z][A-Z0-9_]{3,})\b", text))
    return found


def catalog_rows() -> dict[str, list[str]]:
    rows: dict[str, list[str]] = {}
    for match in TABLE_ROW.finditer(CATALOG.read_text(encoding="utf-8")):
        cells = [c.strip() for c in match.group(1).split("|")]
        if not cells:
            continue
        name = cells[0].strip("`")
        if re.fullmatch(r"[A-Z][A-Z0-9_]+", name):
            rows[name] = cells
    return rows


def main() -> int:
    in_code = code_ids()
    rows = catalog_rows()
    tested = test_ids()

    problems: list[str] = []

    for name in sorted(in_code):
        row = rows.get(name)
        if row is None:
            problems.append(
                f"{name}: no row in docs/DETECTION_CATALOG.md. "
                f"Add technique, layer, weight, false-positive risk and known bypass."
            )
            continue

        # A six-column detector row: SignalId | Technique | Layer | Weight | FP | Notes.
        if len(row) >= 6:
            if is_placeholder(row[4]):
                problems.append(f"{name}: catalog row states no false-positive risk.")
            if is_placeholder(row[5]):
                problems.append(
                    f"{name}: catalog row states no notes / known bypass. "
                    f"If you cannot defeat it, say why."
                )
            if is_placeholder(row[1]):
                problems.append(f"{name}: catalog row states no detection technique.")

        if name not in tested:
            problems.append(f"{name}: no unit test references it by name.")

    if problems:
        print("FAIL: the detection evidence chain is incomplete.\n")
        for problem in problems:
            print(f"  - {problem}")
        print("\nSee CONTRIBUTING.md, 'Definition of done for a detector'.")
        return 1

    planned = sorted(set(rows) - in_code)
    print(
        f"OK: {len(in_code)} implemented signal(s), each catalogued, "
        f"risk-analysed and unit-tested; {len(planned)} still planned."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
