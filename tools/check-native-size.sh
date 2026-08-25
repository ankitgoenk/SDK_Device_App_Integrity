#!/usr/bin/env bash
# Guards the size decision recorded in ADR-0005, now that it is the shipped configuration.
#
# This script used to measure three candidate configurations, because the decision was open.
# It is closed: ANDROID_STL=none with -fno-exceptions, measured at 5,528 bytes against
# 219,472 for the c++_static build it replaced. The job's purpose inverts with it — it no
# longer protects option C from being foreclosed, it protects it from being silently undone.
#
# The failure it exists to catch is someone reintroducing an STL runtime, by setting
# ANDROID_STL back or by adding a dependency that needs it. That costs ~214 KB, so the
# ceiling below sits far enough above today's size to leave phase 3b room to grow, and far
# enough below the STL cost that a reintroduction cannot hide under it.
#
# Usage: tools/check-native-size.sh [abi]
set -euo pipefail

ABI="${1:-arm64-v8a}"
CEILING=65536

NDK="${ANDROID_NDK_HOME:-${ANDROID_HOME:-}/ndk/27.0.12077973}"
TOOLCHAIN="$NDK/build/cmake/android.toolchain.cmake"
STRIP="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip"
SRC="$(dirname "$0")/../integrity-native/src/main/cpp"
WORK="${TMPDIR:-/tmp}/native-size"

if [ ! -f "$TOOLCHAIN" ]; then
  echo "NDK toolchain not found at $TOOLCHAIN" >&2
  exit 1
fi

# Built from the production sources with no rewriting: the thing measured is the thing that
# ships. The old script generated variant copies, which is what let its patterns go stale
# without anything noticing.
rm -rf "$WORK" && mkdir -p "$WORK"
cmake -S "$SRC" -B "$WORK/build" \
  -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN" \
  -DANDROID_ABI="$ABI" -DANDROID_PLATFORM=android-24 \
  -DANDROID_STL=none \
  -DCMAKE_BUILD_TYPE=Release -DINTEGRITY_TOKEN=measurement > /dev/null
cmake --build "$WORK/build" > /dev/null
"$STRIP" --strip-unneeded "$WORK/build/libintegrity.so"

SIZE="$(stat -c%s "$WORK/build/libintegrity.so")"
printf '%s, release, stripped: %s bytes (ceiling %s)\n' "$ABI" "$SIZE" "$CEILING"

if [ "$SIZE" -gt "$CEILING" ]; then
  echo "FAIL: the native library exceeded its ceiling." >&2
  echo "An STL runtime costs ~214 KB; check ANDROID_STL and any new dependency." >&2
  exit 1
fi
echo "OK: the library is within budget and carries no STL runtime."
