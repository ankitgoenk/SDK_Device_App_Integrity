#!/usr/bin/env python3
"""Enforce the evidence chain every detection signal must carry.

A signal is only as trustworthy as what is known about it. For each SignalId that exists
in production code this checks:

  1. it has a row in docs/DETECTION_CATALOG.md               (Signal -> Evidence)
  2. that row states a false-positive risk                   (False-positive analysis)
  3. that row states the technique and a known bypass        (Known bypass)
  4. at least one unit test references it by name            (Unit test)
  5. some `proposedWeights` helper offers it a weight        (Promotion path)

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

# Hard rule 6 ships everything at INFORMATIONAL, and a `proposedWeights` helper is the one
# shipped route to arming it -- so a signal missing from every helper has no promotion path at
# all, whatever weight the catalogue tables for it.
#
# META_* are the SDK describing its own state rather than the device's; weighting them would
# report the SDK's own fragility as a device finding, which is what the empty BASE_WEIGHTS
# exists to prevent. ATT_*/SRV_* are server-side vocabulary.
EXEMPT_FROM_WEIGHTS = ("META_", "ATT_", "SRV_")

# Emitted signals with no proposed weight, and why. Anything here is a decision somebody wrote
# down rather than a helper somebody forgot to update.
NO_PROPOSED_WEIGHT = {
    "APP_NATIVE_LIB_MISMATCH":
        "false positives are dependency skew, not device state; the catalogue says phase 3b "
        "must report expected vs actual tokens first, 'without them the signal is unactionable'",
}


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


def _locate(filename: str) -> pathlib.Path:
    """Finds a source file by name, so moving it between modules is not a silent break.

    This was a hardcoded module path until Policy.kt moved to integrity-model, at which
    point the checker died with a FileNotFoundError traceback rather than saying what it
    could not find. A gate whose failure mode is a stack trace teaches the next person
    nothing.
    """
    matches = [p for p in ROOT.rglob(filename) if "/build/" not in str(p) and "/src/test/" not in str(p)]
    if len(matches) != 1:
        raise SystemExit(
            f"expected exactly one {filename} outside build and test directories, found "
            f"{len(matches)}: {[str(m.relative_to(ROOT)) for m in matches]}"
        )
    return matches[0]


POLICY = _locate("Policy.kt")

# Files that mention a SignalId to weight or score it, rather than to emit it.
NON_PRODUCERS = {"SignalId.kt", "Policy.kt", "RiskScorer.kt"}


BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)
LINE_COMMENT = re.compile(r"//[^\n]*")


def strip_comments(source: str) -> str:
    """A signal named in a KDoc is documented, not emitted."""
    return LINE_COMMENT.sub("", BLOCK_COMMENT.sub("", source))


def excluded_modules() -> set[str]:
    """Modules settings.gradle.kts leaves out of the build cannot emit anything."""
    excluded: set[str] = set()
    properties = (ROOT / "gradle.properties").read_text(encoding="utf-8")
    if "integrity.enableNative=true" not in properties:
        excluded.add("integrity-native")
    return excluded


def producers() -> set[str]:
    """Signals some production file actually emits, in a module that is built."""
    skip = excluded_modules()
    found: set[str] = set()
    for path in ROOT.rglob("*.kt"):
        parts = path.parts
        text = str(path)
        if "/build/" in text or "/src/main/" not in text or path.name in NON_PRODUCERS:
            continue
        if any(module in parts for module in skip):
            continue
        source = strip_comments(path.read_text(encoding="utf-8"))
        found |= set(re.findall(r"SignalId\.([A-Z][A-Z0-9_]+)", source))
    return found


def proposed_weights() -> dict[str, str]:
    """Every id some module's `proposedWeights` helper offers a weight, and which weight.

    The mirror of the check below. That one catches a weight with no producer -- the bug that
    bit twice, in APP_SIGNATURE_MISMATCH and META_NATIVE_UNAVAILABLE. This catches a producer
    with no weight, the same defect reflected: APP_DEX_DIGEST_MISMATCH shipped, sat in
    `RiskScorer.DECISIVE_SIGNALS`, was called "escalates decisively" in four documents, and no
    shipped code path could raise it above INFORMATIONAL.
    """
    found: dict[str, str] = {}
    # Every main source, not `*Detectors.kt`: the first cut globbed on the filename and missed
    # `NativeDetectors`, which lives in `NativeIntegrityDetector.kt`. A parser that silently
    # inspects fewer files than it claims reports a clean bill of health it did not earn --
    # here it did the opposite, and said so, which is the only reason the glob was noticed.
    for path in ROOT.rglob("*.kt"):
        text = str(path)
        if "/build/" in text or "/src/main/" not in text:
            continue
        source = strip_comments(path.read_text(encoding="utf-8"))
        body = re.search(r"fun\s+proposedWeights\b.*", source, re.S)
        if body is None:
            continue
        found.update(
            re.findall(r"SignalId\.([A-Z][A-Z0-9_]+)\s*,\s*Weight\.([A-Z]+)", body.group(0))
        )
    return found


def default_weights() -> dict[str, str]:
    """Weights the default policy applies out of the box."""
    text = POLICY.read_text(encoding="utf-8")
    block = re.search(r"BASE_WEIGHTS[^=]*=\s*(emptyMap\(\)|mapOf\((.*?)\n        \))", text, re.S)
    if block is None or block.group(1).startswith("emptyMap"):
        return {}
    return dict(re.findall(r"SignalId\.([A-Z][A-Z0-9_]+)\s+to\s+Weight\.([A-Z]+)", block.group(2)))


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

    emitted = producers()

    # And the mirror: a producer with no weight has no promotion path at all, so every document
    # calling it decisive describes something no shipped code can do.
    proposed = proposed_weights()
    for name in sorted(emitted):
        if name.startswith(EXEMPT_FROM_WEIGHTS) or name in NO_PROPOSED_WEIGHT:
            continue
        if name not in proposed:
            problems.append(
                f"{name}: emitted by a detector, but no `proposedWeights` helper offers it a "
                f"weight, so nothing can promote it above INFORMATIONAL. Add it to its module's "
                f"helper, or to NO_PROPOSED_WEIGHT with the reason."
            )

    # A weight configured before its producer exists is inert until the detector ships,
    # then activates silently. It has bitten this project twice; make it a build failure.
    for name, weight in sorted(default_weights().items()):
        if weight != "INFORMATIONAL" and name not in emitted:
            problems.append(
                f"{name}: default policy weights it {weight} but nothing emits it. "
                f"Ship the weight with its detector, not before."
            )

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
