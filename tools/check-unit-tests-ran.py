#!/usr/bin/env python3
"""Assert that named JVM unit-test suites actually executed, and that none ran empty.

A green `./gradlew test` means "nothing failed", which is also what you get when a module
drops out of the build, a source set is misconfigured, or a suite is filtered to nothing.
This project has already shipped one job that ran zero tests and reported success; the
instrumented lanes gained a gate for it and the JVM lane never did.

Usage: tools/check-unit-tests-ran.py <fully.qualified.SuiteName>...
"""
import pathlib
import sys
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parent.parent
# Android modules write to testDebugUnitTest/, jvm modules to test/.
PATTERNS = ("**/build/test-results/test/TEST-*.xml",
            "**/build/test-results/testDebugUnitTest/TEST-*.xml")


def main(required: list[str]) -> int:
    suites: dict[str, int] = {}
    empty: list[str] = []
    for pattern in PATTERNS:
        for path in ROOT.glob(pattern):
            root = ET.parse(path).getroot()
            name = root.get("name", path.stem)
            count = int(root.get("tests", "0")) - int(root.get("skipped", "0"))
            suites[name] = suites.get(name, 0) + count
            if count == 0:
                empty.append(f"{name} ({path.relative_to(ROOT)})")

    if not suites:
        print("FAIL: no JVM test results found at all — the test task did not run", file=sys.stderr)
        return 1

    missing = [name for name in required if name not in suites]
    zero = [name for name in required if suites.get(name, 0) == 0]

    total = sum(suites.values())
    print(f"{len(suites)} JVM suite(s), {total} test(s) executed")
    for name in sorted(required):
        print(f"  {suites.get(name, 0):>4}  {name}")

    if missing:
        print("FAIL: required suites produced no results: " + ", ".join(missing), file=sys.stderr)
        return 1
    if zero:
        print("FAIL: required suites ran zero tests: " + ", ".join(zero), file=sys.stderr)
        return 1
    if empty:
        print("FAIL: suites ran with no tests: " + ", ".join(empty), file=sys.stderr)
        return 1

    print(f"OK: every required suite ran, {total} JVM test(s) total.")
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1:]))
