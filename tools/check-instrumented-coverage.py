#!/usr/bin/env python3
"""Fails a job whose instrumented tests silently ran nothing.

`connectedAndroidTest` reports BUILD SUCCESSFUL when it executes zero tests, so a job
whose purpose is to verify a detector family can pass while proving nothing about it.
That is the failure mode CONTRIBUTING.md's "Testing around the 'couldn't verify' state"
exists to prevent, and it was live in this repository's own pipeline: the rooted-image job
ran 0 tests for integrity-detector-root because its only instrumented test was annotated
CleanDeviceOnly and filtered out.

Expectations are named per job rather than inferred. Inference would quietly accept the
deletion of a module's last test as "nothing expected here", which is the same silence
this guard exists to break.

Usage: tools/check-instrumented-coverage.py <module> [<module> ...]
"""
from __future__ import annotations

import pathlib
import sys
import xml.etree.ElementTree as ET

RESULTS_GLOB = "*/build/outputs/androidTest-results/connected/**/*.xml"


def counts_by_module(root: pathlib.Path) -> dict[str, int]:
    totals: dict[str, int] = {}
    for report in root.glob(RESULTS_GLOB):
        parts = report.relative_to(root).parts
        module = parts[0]
        try:
            suite = ET.parse(report).getroot()
        except ET.ParseError as error:
            print(f"unreadable result file {report}: {error}", file=sys.stderr)
            continue
        # A run can emit several suites; the file itself may be the suite or wrap them.
        suites = [suite] if suite.tag == "testsuite" else suite.iter("testsuite")
        for element in suites:
            totals[module] = totals.get(module, 0) + int(element.get("tests", "0"))
    return totals


def main() -> int:
    expected = sys.argv[1:]
    if not expected:
        print(f"usage: {sys.argv[0]} <module> [<module> ...]", file=sys.stderr)
        return 2

    root = pathlib.Path(".").resolve()
    totals = counts_by_module(root)

    if totals:
        for module, count in sorted(totals.items()):
            print(f"  {module}: {count} test(s)")
    else:
        print("  (no instrumented result files found at all)")

    failures = [m for m in expected if totals.get(m, 0) == 0]
    if failures:
        print("", file=sys.stderr)
        for module in failures:
            print(f"FAIL: {module} ran no instrumented tests in this job.", file=sys.stderr)
        print(
            "A job that runs zero tests is not a passing job, it is an absent one. "
            "Either the tests were filtered out (check the runner's annotation "
            "arguments) or they no longer exist.",
            file=sys.stderr,
        )
        return 1

    print(f"OK: every expected module ran at least one instrumented test ({', '.join(expected)}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
