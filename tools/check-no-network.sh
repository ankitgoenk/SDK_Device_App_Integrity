#!/usr/bin/env bash
# Asserts that the shipped SDK cannot perform network IO (ADR-0003, hard rule 5).
#
# The tempting check — "the manifest declares no INTERNET permission" — proves nothing. The
# host app already holds that permission and the SDK inherits it, so a library can open
# sockets all day without declaring anything. What can be checked is whether the shipped
# code is able to *name* the APIs that do it.
#
# JVM: class files record every referenced type in their constant pool, so a class that
# calls Socket carries the string "java/net/Socket" whether or not it is obfuscated.
# Native: an .so that calls connect(2) carries an undefined symbol for it.
#
# Neither is proof against reflection or dlsym, and this file says so rather than implying
# otherwise: it raises the cost of adding networking from "type a line" to "deliberately
# hide it", which is the honest claim.
#
# Usage: tools/check-no-network.sh <file-or-dir>...
set -euo pipefail

FORBIDDEN_JVM='java/net/Socket|java/net/ServerSocket|java/net/URLConnection|java/net/HttpURLConnection|javax/net/ssl|java/nio/channels/SocketChannel|okhttp3/|retrofit2/|org/apache/http|android/net/http'
# Undefined symbols an .so would import to reach the network. dlsym is deliberately here:
# it is the obvious way to get connect() without naming it.
FORBIDDEN_NATIVE='^(socket|connect|bind|listen|accept|sendto|recvfrom|getaddrinfo|gethostbyname|dlsym)$'

fail() { echo "FAIL: $1" >&2; exit 1; }

check_classes() {
  # $2 is what to call the target in output: unpacked archives live in a mktemp dir, and a
  # gate that reports "ok: /tmp/tmp.6dxsU3" tells a reader nothing about what was inspected.
  local target="$1" label="${2:-$1}" found
  # Class files store referenced type names as UTF-8 in the constant pool.
  found=$(grep -rlaE "$FORBIDDEN_JVM" "$target" 2>/dev/null || true)
  if [ -n "$found" ]; then
    echo "$found" | while read -r f; do
      echo "  $f references:" >&2
      grep -oaE "$FORBIDDEN_JVM" "$f" | sort -u | sed 's/^/    /' >&2
    done
    fail "$label references networking APIs; the SDK performs no network IO (ADR-0003)"
  fi
  echo "  ok: $label names no networking API"
}

check_so() {
  local target="$1" found
  # Strip @GLIBC_2.2.5-style version suffixes before matching. Without this the anchored
  # pattern silently matches nothing on a versioned platform — which the first version of
  # this script did, accepting a library that called connect() outright. Android's bionic
  # emits unversioned symbols, so CI would have passed while the check did nothing.
  found=$(nm -D --undefined-only "$target" 2>/dev/null \
    | awk '{print $NF}' | sed 's/@.*//' | grep -E "$FORBIDDEN_NATIVE" || true)
  if [ -n "$found" ]; then
    echo "$found" | sed 's/^/    /' >&2
    fail "$target imports networking symbols"
  fi
  echo "  ok: $target imports no networking symbol"
}

# --self-test builds a positive control and asserts this script rejects it. Without it the
# script has the failure mode every gate here has had at least once: reporting "ok" because it
# looked in the wrong place, not because the artifact is clean. The jar case earned this
# specifically — grepping a jar directly finds nothing, since its entries are deflated, so the
# obvious implementation passes a jar that opens a Socket.
if [ "${1:-}" = "--self-test" ]; then
  work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
  mkdir -p "$work/pkg"
  # Repetitive filler so the zip entry is deflated rather than stored; a stored entry would
  # let a direct grep succeed and the control would prove nothing.
  { head -c 4000 /dev/zero | tr '\0' 'a'; printf 'java/net/Socket'; } > "$work/pkg/Bad.class"
  (cd "$work" && zip -q -r bad.jar pkg)

  # 1. The archive must not reveal the string directly — otherwise this control is not
  #    exercising the unpack path at all.
  if grep -qaE "$FORBIDDEN_JVM" "$work/bad.jar"; then
    echo "SELF-TEST INVALID: the jar was not compressed, so it proves nothing" >&2; exit 1
  fi
  # 2. The script must reject it anyway.
  if "$0" "$work/bad.jar" >/dev/null 2>&1; then
    echo "SELF-TEST FAILED: a jar naming java/net/Socket was accepted" >&2; exit 1
  fi
  # 3. And must still accept a clean jar, or "rejects everything" would pass step 2.
  mkdir -p "$work/ok"; head -c 4000 /dev/zero | tr '\0' 'a' > "$work/ok/Fine.class"
  (cd "$work" && zip -q -r ok.jar ok)
  if ! "$0" "$work/ok.jar" >/dev/null 2>&1; then
    echo "SELF-TEST FAILED: a clean jar was rejected" >&2; exit 1
  fi
  echo "OK: self-test passed — rejects a compressed jar naming a networking API, accepts a clean one."
  exit 0
fi

[ "$#" -gt 0 ] || { echo "usage: $0 <file-or-dir>..." >&2; exit 2; }

for target in "$@"; do
  case "$target" in
    *.aar)
      work=$(mktemp -d)
      unzip -q -o "$target" -d "$work"
      echo "--- $target"
      [ -f "$work/classes.jar" ] && { mkdir -p "$work/classes"; unzip -q -o "$work/classes.jar" -d "$work/classes"; check_classes "$work/classes" "$target"; }
      while IFS= read -r so; do check_so "$so"; done < <(find "$work" -name '*.so')
      rm -rf "$work"
      ;;
    *.jar)
      # A jar must be unpacked before grepping. Its entries are deflated, so the constant-pool
      # strings are not present verbatim in the archive: grepping the jar directly finds
      # nothing and passes, on a jar that opens a Socket. That is worse than no check, because
      # it reports "ok".
      work=$(mktemp -d)
      unzip -q -o "$target" -d "$work"
      echo "--- $target"
      check_classes "$work" "$target"
      rm -rf "$work"
      ;;
    *.so) echo "--- $target"; check_so "$target" ;;
    *)    echo "--- $target"; check_classes "$target" ;;
  esac
done

echo "OK: nothing shipped can name a networking API."
