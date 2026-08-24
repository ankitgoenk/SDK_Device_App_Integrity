#!/usr/bin/env python3
"""Fail the build when code and docs/DETECTION_CATALOG.md disagree about signal ids.

A signal that exists in code but not in the catalog has no documented technique, weight,
false-positive analysis or known bypass — which is exactly the review this project refuses
to skip. A catalogued id with no implementation is a promise we are not keeping, so it must
be marked as planned rather than silently listed.

Usage: tools/check-signal-catalog.py [--allow-unimplemented]
"""
from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
CATALOG = ROOT / "docs" / "DETECTION_CATALOG.md"

# public val ROOT_SU_BINARY: SignalId = SignalId("ROOT_SU_BINARY")
CODE_ID = re.compile(r'SignalId\(\s*"([A-Z][A-Z0-9_]+)"\s*\)')
# | `ROOT_SU_BINARY` | ... |
CATALOG_ID = re.compile(r'^\|\s*`([A-Z][A-Z0-9_]+)`\s*\|', re.MULTILINE)

# Ids that exist only to describe the scaffold itself.
EXEMPT = {"META_ENGINE_NOT_IMPLEMENTED"}


def code_ids() -> set[str]:
    found: set[str] = set()
    for path in ROOT.rglob("*.kt"):
        if "/build/" in str(path) or "/src/test/" in str(path):
            continue
        found |= set(CODE_ID.findall(path.read_text(encoding="utf-8")))
    return found - EXEMPT


def catalog_ids() -> set[str]:
    return set(CATALOG_ID.findall(CATALOG.read_text(encoding="utf-8")))


def main() -> int:
    allow_unimplemented = "--allow-unimplemented" in sys.argv

    in_code = code_ids()
    in_docs = catalog_ids()

    undocumented = sorted(in_code - in_docs)
    unimplemented = sorted(in_docs - in_code)

    if undocumented:
        print("FAIL: signal ids in code with no docs/DETECTION_CATALOG.md entry:")
        for name in undocumented:
            print(f"  - {name}")
        print("\nAdd a row with technique, layer, weight, FP risk and known bypass.")

    if unimplemented and not allow_unimplemented:
        print(f"\nNote: {len(unimplemented)} catalogued id(s) not yet implemented "
              f"(expected while phases 2-7 are outstanding).")

    if undocumented:
        return 1

    print(f"OK: {len(in_code)} implemented id(s), all catalogued; "
          f"{len(unimplemented)} still planned.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
