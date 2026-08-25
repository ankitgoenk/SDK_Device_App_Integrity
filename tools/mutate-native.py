#!/usr/bin/env python3
"""Deliberately breaks the native code and requires the tests to notice.

This is the load-bearing test in this repository, because it is the only one that answers
the question the others cannot ask about themselves: did that suite actually test anything?
Every anti-vacuity check added so far — proving a reintroduced try/catch fails to compile,
watching an instrumented count go 5 to 6, printing SKIPPED when a property is not exercised
— is a hand-written mutation test. This generalises them.

A mutant that the suite fails to notice is a hole in the suite, not a bug in the code.

Mutations are exact string replacements and every one asserts that its pattern was found.
A silently unmatched pattern would report a perfect score while mutating nothing, which is
precisely how tools/rewrite-native-variant.py went stale and had to be deleted.

Usage: tools/mutate-native.py [--keep-going]
"""
from __future__ import annotations

import dataclasses
import pathlib
import shutil
import subprocess
import sys
import tempfile

CPP = pathlib.Path(__file__).resolve().parent.parent / "integrity-native/src/main/cpp"
SOURCES = ("selfcheck.cpp", "maps.cpp", "safe_read.cpp")
TESTS = ("test/native_host_test.cpp", "test/native_property_test.cpp")


@dataclasses.dataclass(frozen=True)
class Mutation:
    file: str
    before: str
    after: str
    describes: str
    # Some defects exist only at one pointer width. off_t truncation is a no-op on a 64-bit
    # host, where off_t is already 64-bit, so a 64-bit-only run would report it survived
    # when it was simply never tried. Untried is not the same as uncaught, and reporting
    # one as the other is the mistake this tool exists to catch.
    needs_width: str = ""


MUTATIONS = (
    # --- maps.cpp: the hex parser's overflow guard --------------------------------------
    Mutation("maps.cpp", "if (value > (UINTPTR_MAX - digit) / kHexBase) {",
             "if (false) {", "hex overflow guard removed entirely"),
    Mutation("maps.cpp", "if (value > (UINTPTR_MAX - digit) / kHexBase) {",
             "if (value >= (UINTPTR_MAX - digit) / kHexBase) {", "hex overflow guard off by one"),
    Mutation("maps.cpp", "if (digits == 0) {", "if (false) {",
             "empty number accepted as zero"),
    # --- maps.cpp: grammar and consistency ----------------------------------------------
    Mutation("maps.cpp", "if (end < start) {", "if (false) {", "inverted range accepted"),
    Mutation("maps.cpp", "if (index + 4 > length) {", "if (index + 5 > length) {",
             "permission-field length check off by one"),
    Mutation("maps.cpp", "if (index >= length || line[index] != '-') {",
             "if (index > length || line[index] != '-') {", "separator bounds check off by one"),
    Mutation("maps.cpp", "(p != 'p' && p != 's')", "(p != 'p' && p != 's' && p != '-')",
             "private/shared flag accepts a third value"),
    Mutation("maps.cpp", "if (line == nullptr || out == nullptr || length == 0) {",
             "if (out == nullptr || length == 0) {", "null line no longer rejected"),
    # --- maps.cpp: rangeIsReadable, the total specification ------------------------------
    Mutation("maps.cpp", "if (address > UINTPTR_MAX - length) {", "if (false) {",
             "range overflow guard removed"),
    Mutation("maps.cpp", "if (address > UINTPTR_MAX - length) {",
             "if (address >= UINTPTR_MAX - length) {", "range overflow guard off by one"),
    Mutation("maps.cpp", "if (address < range.start || address + length > range.end) {",
             "if (address < range.start || address + length >= range.end) {",
             "containment upper bound off by one"),
    Mutation("maps.cpp", "if (address < range.start || address + length > range.end) {",
             "if (address <= range.start || address + length > range.end) {",
             "containment lower bound off by one"),
    Mutation("maps.cpp", "if (!range.readable) {", "if (false) {",
             "unreadable mappings treated as readable"),
    Mutation("maps.cpp", "if (length == 0) {\n        return kStatusInvalidInput;",
             "if (false) {\n        return kStatusInvalidInput;",
             "zero-length read no longer invalid"),
    # --- safe_read.cpp ------------------------------------------------------------------
    Mutation("safe_read.cpp", "#define _FILE_OFFSET_BITS 64", "#define _FILE_OFFSET_BITS 32",
             "the off_t truncation bug, reintroduced", needs_width="32-bit"),
    Mutation("safe_read.cpp", "if (out == nullptr || length == 0 || length > kMaxSafeReadBytes) {",
             "if (out == nullptr || length == 0) {", "oversized reads no longer refused"),
    Mutation("safe_read.cpp", "if (address > UINTPTR_MAX - length) {", "if (false) {",
             "read overflow guard removed"),
    Mutation("safe_read.cpp", "if (got == 0) {", "if (false) {",
             "short read no longer treated as failure"),
    Mutation("safe_read.cpp", "return kStatusUnavailable;\n    }\n\n    NativeStatus status",
             "return kStatusOk;\n    }\n\n    NativeStatus status",
             "an unopenable /proc/self/mem reported as success"),
    # --- selfcheck.cpp ------------------------------------------------------------------
    Mutation("selfcheck.cpp", "return difference == 0;", "return true;",
             "token comparison always succeeds"),
    Mutation("selfcheck.cpp", "difference |= static_cast<unsigned char>(*a) ^ static_cast<unsigned char>(*b);",
             "difference |= 0;", "token length difference ignored, so a prefix matches"),
    Mutation("selfcheck.cpp", "if (expected == nullptr) {", "if (false) {",
             "null token no longer rejected"),
)

COMPILE = (
    "g++ -std=c++17 -Wall -Wextra -Werror -fno-exceptions "
    "-DINTEGRITY_BUILD_TOKEN='\"ci-host-token\"'"
)

# Both pointer widths, mirroring the host test job. Found the hard way: reintroducing the
# off_t truncation survived every 64-bit suite, because on a 64-bit host off_t is already
# 64-bit and the mutation changes nothing. It is a real bug only at 32-bit width, where the
# static_assert refuses to compile it. A mutation run at one width silently under-reports.
# Three configurations, because a mutant can be invisible in two of them.
#
# AddressSanitizer earns its place: dropping the parser's `index >= length` bound to
# `index >` produces identical return values for every input, so no assertion can see it —
# but it reads one byte past the caller's buffer. The parser's contract is (pointer,
# length), and /proc data is not necessarily NUL-terminated, so that is a real out-of-bounds
# read in a security library. Only a sanitizer observes it.
ALL_WIDTHS = (
    ("64-bit", ""),
    ("64-bit+asan", "-fsanitize=address -g"),
    ("32-bit", "-m32"),
)


def available_widths() -> tuple[tuple[str, str], ...]:
    """Widths this machine can actually build and run.

    A missing 32-bit toolchain must be announced, not absorbed. Silently dropping it would
    report a full mutation score for a run that never tested half of what it claims — the
    failure this whole exercise exists to prevent.
    """
    usable = []
    for width, flag in ALL_WIDTHS:
        probe = subprocess.run(
            f"echo 'int main(){{return 0;}}' | g++ {flag} -x c++ - -o /dev/null",
            shell=True, capture_output=True, text=True,
        )
        if probe.returncode == 0:
            usable.append((width, flag))
        else:
            print(f"NOTE: no {width} toolchain here; mutants will not be tried at that "
                  f"width. Install gcc-multilib for full coverage (CI has it).")
    return tuple(usable)

# A mutant that removes a loop's exit condition hangs rather than failing. That is still a
# detected defect, but the driver must not hang with it.
RUN_TIMEOUT_SECONDS = 120


def build_and_run(work: pathlib.Path, binary: pathlib.Path,
                  widths: tuple[tuple[str, str], ...]) -> tuple[bool, str]:
    """Returns (all_suites_passed, note). A compile failure counts as a kill: it cannot ship.

    Each test file has its own main(), so they are built and run as separate binaries. A
    mutant survives only if *every* suite still passes.
    """
    sources = " ".join(str(work / s) for s in SOURCES)
    for width, flag in widths:
        for test in TESTS:
            compiled = subprocess.run(
                f"{COMPILE} {flag} {sources} {work / test} -o {binary}",
                shell=True, capture_output=True, text=True,
            )
            if compiled.returncode != 0:
                return False, f"rejected at compile time ({width}, {pathlib.Path(test).name})"

            try:
                ran = subprocess.run([str(binary)], capture_output=True, text=True,
                                     timeout=RUN_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                return False, f"hung ({width}, {pathlib.Path(test).name})"
            if ran.returncode != 0:
                return False, f"caught by {pathlib.Path(test).name} at {width}"
    return True, "every suite passed at " + ", ".join(w for w, _ in widths)


def main() -> int:
    keep_going = "--keep-going" in sys.argv
    survivors: list[Mutation] = []
    untried: list[Mutation] = []
    killed = 0

    widths = available_widths()
    names = {w for w, _ in widths}
    if not widths:
        print("ABORT: no usable C++ toolchain.", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        binary = root / "mutant"

        # Sanity: the unmutated suite must pass, or every mutant looks killed for free.
        pristine = root / "pristine"
        shutil.copytree(CPP, pristine)
        passed, note = build_and_run(pristine, binary, widths)
        if not passed:
            print(f"ABORT: the suite does not pass unmutated ({note}).", file=sys.stderr)
            print("Every mutant would appear killed, and the score would be meaningless.",
                  file=sys.stderr)
            return 2
        print(f"baseline: unmutated suite passes ({len(MUTATIONS)} mutants to try)\n")

        for index, mutation in enumerate(MUTATIONS, start=1):
            work = root / f"m{index}"
            shutil.rmtree(work, ignore_errors=True)
            shutil.copytree(CPP, work)

            target = work / mutation.file
            text = target.read_text(encoding="utf-8")
            if mutation.before not in text:
                print(f"ERROR: mutation {index} matched nothing in {mutation.file}.",
                      file=sys.stderr)
                print(f"  looking for: {mutation.before!r}", file=sys.stderr)
                print("  A mutation list that silently stops mutating reports a perfect "
                      "score for doing nothing.", file=sys.stderr)
                return 2
            target.write_text(text.replace(mutation.before, mutation.after, 1), encoding="utf-8")

            if mutation.needs_width and mutation.needs_width not in names:
                untried.append(mutation)
                print(f"  NOT TRIED {mutation.file}: {mutation.describes} "
                      f"(needs {mutation.needs_width})")
                continue

            passed, note = build_and_run(work, binary, widths)
            if passed:
                survivors.append(mutation)
                print(f"  SURVIVED  {mutation.file}: {mutation.describes}")
                if not keep_going:
                    continue
            else:
                killed += 1
                print(f"  killed    {mutation.file}: {mutation.describes} ({note})")

    total = len(MUTATIONS)
    tried_at = ", ".join(w for w, _ in widths)
    print(f"\nmutation score: {killed}/{total - len(untried)} killed "
          f"(configurations: {tried_at})")
    if untried:
        print(f"{len(untried)} mutant(s) not tried here for want of a toolchain:")
        for mutation in untried:
            print(f"  - {mutation.describes} (needs {mutation.needs_width})")
        print("Not the same as caught. CI runs every configuration.")

    if survivors:
        print("\nThese changes broke the code and no test noticed:", file=sys.stderr)
        for mutation in survivors:
            print(f"  - {mutation.file}: {mutation.describes}", file=sys.stderr)
        print("\nEach one is a gap in the tests, not a defect in the code. Add a case that "
              "fails against that mutant, then re-run.", file=sys.stderr)
        return 1

    print("OK: every mutant was caught.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
