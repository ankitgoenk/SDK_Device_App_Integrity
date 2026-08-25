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
  local target="$1" found
  # Class files store referenced type names as UTF-8 in the constant pool.
  found=$(grep -rlaE "$FORBIDDEN_JVM" "$target" 2>/dev/null || true)
  if [ -n "$found" ]; then
    echo "$found" | while read -r f; do
      echo "  $f references:" >&2
      grep -oaE "$FORBIDDEN_JVM" "$f" | sort -u | sed 's/^/    /' >&2
    done
    fail "$target references networking APIs; the SDK performs no network IO (ADR-0003)"
  fi
  echo "  ok: $target names no networking API"
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

[ "$#" -gt 0 ] || { echo "usage: $0 <file-or-dir>..." >&2; exit 2; }

for target in "$@"; do
  case "$target" in
    *.aar)
      work=$(mktemp -d)
      unzip -q -o "$target" -d "$work"
      echo "--- $target"
      [ -f "$work/classes.jar" ] && { mkdir -p "$work/classes"; unzip -q -o "$work/classes.jar" -d "$work/classes"; check_classes "$work/classes"; }
      while IFS= read -r so; do check_so "$so"; done < <(find "$work" -name '*.so')
      rm -rf "$work"
      ;;
    *.so) echo "--- $target"; check_so "$target" ;;
    *)    echo "--- $target"; check_classes "$target" ;;
  esac
done

echo "OK: nothing shipped can name a networking API."
