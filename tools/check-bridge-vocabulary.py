#!/usr/bin/env python3
"""Assert the TypeScript bridge spells the same vocabularies as the Kotlin.

Hard rule 9: "Neither vocabulary may contain a name a caller could read as permission.
`Verdict` (client) and `DeviceState` (server) both had a `TRUSTED` rung and both lost it, and a
test pins the membership of each."

Those two tests exist, in Kotlin. `integrations/react-native/integrity.d.ts` is a *third*
vocabulary and nothing pinned it, so it kept `TRUSTED` in both unions long after ADR-0008 and
ADR-0009 removed the name -- while also missing `NO_EVIDENCE_OF_COMPROMISE` from both and
`LOW_RISK` from one. A React Native integrator codes against this file, not against the ADRs.

The failure it invites is not the obvious one. Writing `decision === 'TRUSTED'` against a server
that never sends it just blocks every sensitive action, and somebody notices in a day. The
dangerous fix is the next one: read the wire, see `NO_EVIDENCE_OF_COMPROMISE`, conclude "they
renamed it", and treat an absence as a pass. That is the hole ADR-0007 closed -- send no signals,
receive no incrimination, be let in -- and the rename was the whole defence against reaching for
it.

Deliberately not `tsc --noEmit`, which ADR-0006's checklist names as the missing enforcement here.
`tsc` proves the file is internally consistent; a union of four wrong strings type-checks
perfectly. What has to be checked is membership against the Kotlin, which is what this does.

Usage: tools/check-bridge-vocabulary.py [--self-test]
"""
from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
BRIDGE = ROOT / "integrations" / "react-native" / "integrity.d.ts"

# The vocabularies to compare, by name. Both sides must declare the same members.
VOCABULARIES = ("Verdict", "DeviceState")

# Names removed by ADR-0008 and ADR-0009. A member matching one of these is not a drift but a
# regression, and gets its own message.
FORBIDDEN_MEMBERS = {"TRUSTED"}

BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)
LINE_COMMENT = re.compile(r"//[^\n]*")


def _strip_comments(source: str) -> str:
    """A name in a KDoc or a JSDoc is discussed, not declared.

    Load-bearing: the TypeScript `Verdict` block carries a paragraph explaining why `TRUSTED`
    was removed, and it names it. A raw text search would flag the explanation as the defect.
    """
    return LINE_COMMENT.sub("", BLOCK_COMMENT.sub("", source))


def _locate(filename: str) -> pathlib.Path:
    """Find a source file by name, so moving it between modules is not a silent break."""
    matches = [
        p for p in ROOT.rglob(filename)
        if "/build/" not in str(p) and "/src/test/" not in str(p)
    ]
    if len(matches) != 1:
        raise SystemExit(
            f"expected exactly one {filename} outside build and test directories, found "
            f"{len(matches)}: {[str(m.relative_to(ROOT)) for m in matches]}"
        )
    return matches[0]


def kotlin_enum(source: str, name: str) -> set[str]:
    """Members of `enum class <name> { ... }`, ignoring KDoc and trailing commas."""
    match = re.search(
        rf"enum\s+class\s+{re.escape(name)}\s*\{{(.*?)\n\}}", _strip_comments(source), re.S
    )
    if match is None:
        return set()
    return set(re.findall(r"\b([A-Z][A-Z0-9_]{2,})\b", match.group(1)))


def typescript_union(source: str, name: str) -> set[str]:
    """Members of `export type <name> = 'A' | 'B';`, across however many lines."""
    match = re.search(
        rf"export\s+type\s+{re.escape(name)}\s*=(.*?);", _strip_comments(source), re.S
    )
    if match is None:
        return set()
    return set(re.findall(r"'([A-Z][A-Z0-9_]*)'", match.group(1)))


def forbidden_literals(source: str) -> set[str]:
    """Any removed name appearing as a string literal, wherever it sits.

    The named-type comparison below only sees `export type X = ...`. Inlining the union back
    into the interface -- which is how this file was written before the types were named --
    would sidestep it, and that is the exact shape the defect had. So the removed names are
    also searched for directly, everywhere.
    """
    literals = set(re.findall(r"'([A-Z][A-Z0-9_]*)'", _strip_comments(source)))
    return literals & FORBIDDEN_MEMBERS


def check(kotlin_sources: dict[str, str], bridge: str) -> list[str]:
    problems: list[str] = []

    for member in sorted(forbidden_literals(bridge)):
        problems.append(
            f"the bridge offers '{member}' as a value somewhere — ADR-0008 and ADR-0009 removed "
            f"that name from both vocabularies because a caller reads it as permission"
        )

    for name in VOCABULARIES:
        kotlin = kotlin_enum(kotlin_sources[name], name)
        # Vacuity guard. An empty side means the parser broke, not the documents -- and a
        # checker that passes because it found nothing is the failure this repository keeps
        # hitting.
        if not kotlin:
            problems.append(f"parsed zero members from Kotlin `enum class {name}` — the parser is broken")
            continue

        bridged = typescript_union(bridge, name)
        if not bridged:
            problems.append(
                f"`export type {name}` is missing from the bridge, or its members did not parse"
            )
            continue

        for member in sorted(bridged - kotlin - FORBIDDEN_MEMBERS):
            problems.append(
                f"bridge `{name}` offers '{member}', which Kotlin `{name}` does not declare"
            )
        for member in sorted(kotlin - bridged):
            problems.append(
                f"Kotlin `{name}` declares {member}, which the bridge `{name}` omits "
                f"(a value the app will receive and cannot represent)"
            )
    return problems


def _sources() -> tuple[dict[str, str], str]:
    return (
        {
            "Verdict": _locate("Model.kt").read_text(encoding="utf-8"),
            "DeviceState": _locate("Submission.kt").read_text(encoding="utf-8"),
        },
        BRIDGE.read_text(encoding="utf-8"),
    )


def self_test() -> int:
    """Prove the checker rejects the broken cases. Hard rule 10: a gate that cannot fail is
    worse than no gate."""
    kotlin, bridge = _sources()
    if check(kotlin, bridge):
        print("SELF-TEST ABORT: the real bridge does not pass, so a mutant proves nothing.",
              file=sys.stderr)
        return 1

    cases = [
        # The regression this gate exists for, reproduced exactly.
        ("`TRUSTED` put back into the client vocabulary",
         bridge.replace("  | 'NO_EVIDENCE_OF_COMPROMISE'\n  | 'LOW_RISK'",
                        "  | 'TRUSTED'\n  | 'LOW_RISK'", 1)),
        ("a rung the Kotlin declares and the bridge drops",
         bridge.replace("  | 'LOW_RISK'\n", "", 1)),
        ("a rung the bridge invents",
         bridge.replace("  | 'INSUFFICIENT_EVIDENCE';", "  | 'PROBABLY_FINE';", 1)),
        ("the whole DeviceState union removed",
         bridge.replace("export type DeviceState =", "export type DeviceStateOld =", 1)),
    ]

    failures = 0
    for label, mutated in cases:
        if mutated == bridge:
            print(f"  NOT APPLIED: {label} — the mutation text no longer matches the document",
                  file=sys.stderr)
            failures += 1
            continue
        if not check(kotlin, mutated):
            print(f"  SURVIVED: {label}", file=sys.stderr)
            failures += 1
        else:
            print(f"  killed: {label}")

    if failures:
        print(f"\nSELF-TEST FAILED: {failures} case(s) the gate does not catch.", file=sys.stderr)
        return 1
    print(f"\nSELF-TEST OK: {len(cases)} deliberately broken bridges, all rejected.")
    return 0


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()

    if not BRIDGE.exists():
        print(f"FAIL: {BRIDGE} is missing.", file=sys.stderr)
        return 1

    problems = check(*_sources())
    if problems:
        print("FAIL: the TypeScript bridge no longer spells the Kotlin vocabularies.\n",
              file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        print("\nAn integrator codes against this file, not against the ADRs. A vocabulary it "
              "gets wrong is one they will implement.", file=sys.stderr)
        return 1

    counts = ", ".join(
        f"{name} ({len(typescript_union(BRIDGE.read_text(encoding='utf-8'), name))})"
        for name in VOCABULARIES
    )
    print(f"OK: the bridge spells the Kotlin vocabularies exactly — {counts}.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
