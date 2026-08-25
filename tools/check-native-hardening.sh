#!/usr/bin/env bash
# Asserts the hardening properties of one shipped libintegrity.so.
#
# Runs against the .so extracted from the release AAR, never a build intermediate.
# Globbing intermediates once picked up a pre-strip stage that was never going to ship,
# which made the check a statement about the build directory rather than the artifact.
#
# Usage: tools/check-native-hardening.sh <path-to-libintegrity.so>
set -euo pipefail

SO="${1:?usage: $0 <libintegrity.so>}"
BUDGET_BYTES="${INTEGRITY_SO_BUDGET:-262144}"

size=$(stat -c%s "$SO")
echo "--- $SO ($size bytes)"

# ADR-0002: methods are registered dynamically, so there is no greppable entry point.
if nm -D --defined-only "$SO" 2>/dev/null | grep -q 'Java_io_integrity'; then
  echo "FAIL: exports a Java_io_integrity_* symbol" >&2
  exit 1
fi

if readelf -S "$SO" | grep -q '\.debug_info'; then
  echo "FAIL: not stripped" >&2
  exit 1
fi

if [ "$size" -gt "$BUDGET_BYTES" ]; then
  echo "FAIL: exceeds the $BUDGET_BYTES byte per-ABI budget" >&2
  exit 1
fi

# Full RELRO is two separate things, and having only the first is the trap.
#
# GNU_RELRO marks a region to be made read-only after relocation. On its own it leaves
# lazy binding enabled, so .got.plt — the part an attacker actually wants to overwrite to
# redirect an imported call — stays writable for the life of the process. BIND_NOW resolves
# every import at load, which is what allows the whole GOT into the read-only region.
#
# This is a precondition for the HOOK_PLT_GOT design: whether the GOT is writable at
# runtime decides whether that detector is worth building, or whether a link flag was the
# real answer. See docs/detectors/HOOK_PLT_GOT.md section 3.
if ! readelf -l "$SO" | grep -q 'GNU_RELRO'; then
  echo "FAIL: no GNU_RELRO segment; relocations stay writable after load." >&2
  echo "  Fix the link flags (-Wl,-z,relro,-z,now), do not write a detector for this." >&2
  exit 1
fi

# DT_BIND_NOW appears as FLAGS/BIND_NOW, DF_1_NOW as FLAGS_1 with NOW. Either establishes it.
if ! readelf -d "$SO" | grep -Eq 'BIND_NOW|Flags:.*\bNOW\b'; then
  echo "FAIL: GNU_RELRO present but no BIND_NOW, so this is partial RELRO." >&2
  echo "  Lazy binding leaves .got.plt writable for the life of the process, which is" >&2
  echo "  exactly the region GOT redirection targets. Add -Wl,-z,now." >&2
  exit 1
fi

echo "    ok: unexported, stripped, within budget, full RELRO (GNU_RELRO + BIND_NOW)"
