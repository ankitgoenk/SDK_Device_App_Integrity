#!/usr/bin/env python3
"""Rewrites a copy of the native sources into a measurement variant.

Kept out of the CI YAML because a heredoc nested inside a YAML block scalar does not
terminate the way it looks like it does, and because a transformation this fiddly should
be runnable — and checkable — locally.
"""
from __future__ import annotations

import pathlib
import re
import sys

VARIANTS = ("no-stdexcept", "no-exceptions")


def rewrite(directory: pathlib.Path, variant: str) -> None:
    source = directory / "integrity.cpp"
    text = source.read_text(encoding="utf-8")

    text = text.replace("#include <stdexcept>\n", "")

    if variant == "no-stdexcept":
        # Still throws, so containment is unchanged; just never an STL type.
        text = re.sub(
            r'throw std::runtime_error\([^;]*\);',
            "throw integrity::kProvokedFailure;",
            text,
        )
        text = text.replace("} catch (...) {", "} catch (...) {")
    else:
        # No unwinding at all: the throw becomes the return it was going to produce.
        text = re.sub(
            r'throw std::runtime_error\([^;]*\);',
            "return integrity::kProvokedFailure;",
            text,
        )
        text = re.sub(r"\n[ \t]*try \{", "", text)
        text = re.sub(r"\n[ \t]*\} catch \(\.\.\.\) \{[^}]*\}", "", text)

        cmake = directory / "CMakeLists.txt"
        cmake.write_text(cmake.read_text(encoding="utf-8").replace("-fexceptions", "-fno-exceptions"))

    source.write_text(text, encoding="utf-8")


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[2] not in VARIANTS:
        print(f"usage: {sys.argv[0]} <dir> <{'|'.join(VARIANTS)}>", file=sys.stderr)
        return 2
    rewrite(pathlib.Path(sys.argv[1]), sys.argv[2])
    return 0


if __name__ == "__main__":
    sys.exit(main())
