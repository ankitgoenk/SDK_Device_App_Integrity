#!/usr/bin/env python3
"""Assert the module tables in README.md and docs/ARCHITECTURE.md list every Gradle module.

The narrow, mechanical slice of doc drift that can be checked. It exists because both tables
silently omitted `integrity-model` for a whole PR after the module was added, and because
CLAUDE.md described the repository as "documentation only, no code yet" through twenty-one
merged PRs. A table nobody verifies is a table that is wrong.

Grouped rows are honoured, so `integrity-detector-{root,hooking}` counts for both.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
TABLES = {
    "README.md": ROOT / "README.md",
    "docs/ARCHITECTURE.md": ROOT / "docs" / "ARCHITECTURE.md",
}
# Sample and build-only modules are not part of the published surface these tables describe,
# but they are listed today, so require them too rather than special-casing.
BRACES = re.compile(r"^(.*?)\{([^}]*)\}(.*)$")


def modules() -> list[str]:
    text = (ROOT / "settings.gradle.kts").read_text(encoding="utf-8")
    return sorted(set(re.findall(r'include\("[:]?([A-Za-z0-9._-]+)"\)', text)))


def documented(path: pathlib.Path) -> set[str]:
    """Every `code-spanned` name in a markdown table cell, with {a,b} groups expanded."""
    found: set[str] = set()
    for raw in re.findall(r"^\|\s*`([^`]+)`", path.read_text(encoding="utf-8"), re.M):
        m = BRACES.match(raw)
        if m:
            head, inner, tail = m.groups()
            found.update(f"{head}{part.strip()}{tail}" for part in inner.split(","))
        else:
            found.add(raw)
    return found


def main() -> int:
    declared = modules()
    if not declared:
        print("FAIL: parsed zero modules from settings.gradle.kts — the parser is broken, "
              "not the docs", file=sys.stderr)
        return 1

    problems = []
    for label, path in TABLES.items():
        if not path.exists():
            problems.append(f"{label}: missing")
            continue
        listed = documented(path)
        for module in declared:
            if module not in listed:
                problems.append(f"{label}: no row for `{module}`")

    if problems:
        print("FAIL: the module tables do not match settings.gradle.kts.\n", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        print("\nAdd the row, or remove the module. A stale table is worse than none.",
              file=sys.stderr)
        return 1

    print(f"OK: {len(declared)} module(s) documented in {len(TABLES)} table(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
