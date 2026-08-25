#!/usr/bin/env bash
# Measures the native size trade with numbers instead of argument.
#
# The library sits at 219 KB for one string comparison and phase 3b spends whatever is
# left of the budget. The usual framing is "exceptions or not", but the more promising
# option is in between: keep catch (...) for containment and stop throwing STL types, on
# the theory that most of the cost is the libc++ that <stdexcept> drags in rather than
# unwinding support itself.
#
# Variants are generated copies. Production sources stay untouched until the data says
# which way to go.
#
# Usage: tools/measure-native-size.sh [abi]
set -euo pipefail

ABI="${1:-arm64-v8a}"
NDK="${ANDROID_NDK_HOME:-${ANDROID_HOME:-}/ndk/27.0.12077973}"
TOOLCHAIN="$NDK/build/cmake/android.toolchain.cmake"
STRIP="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip"
SRC="$(dirname "$0")/../integrity-native/src/main/cpp"
WORK="${TMPDIR:-/tmp}/native-size"

if [ ! -f "$TOOLCHAIN" ]; then
  echo "NDK toolchain not found at $TOOLCHAIN" >&2
  exit 1
fi

prepare() {
  rm -rf "$WORK/$1" && mkdir -p "$WORK/$1"
  cp "$SRC/CMakeLists.txt" "$SRC/integrity.cpp" "$SRC/selfcheck.cpp" "$SRC/selfcheck.h" "$WORK/$1/"
}

measure() {
  local name="$1"; shift
  cmake -S "$WORK/$name" -B "$WORK/build-$name" \
    -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN" \
    -DANDROID_ABI="$ABI" -DANDROID_PLATFORM=android-24 \
    -DCMAKE_BUILD_TYPE=Release -DINTEGRITY_TOKEN=measurement "$@" > /dev/null
  cmake --build "$WORK/build-$name" > /dev/null
  "$STRIP" --strip-unneeded "$WORK/build-$name/libintegrity.so"
  printf '%-24s %8s bytes\n' "$name" "$(stat -c%s "$WORK/build-$name/libintegrity.so")"
}

echo "=== $ABI, release, stripped ==="

# A: exactly what ships today.
prepare a-stdexcept
measure a-stdexcept -DANDROID_STL=c++_static

# B: containment kept, but nothing thrown from the STL.
prepare b-no-stdexcept
"$(dirname "$0")/rewrite-native-variant.py" "$WORK/b-no-stdexcept" no-stdexcept
measure b-no-stdexcept -DANDROID_STL=c++_static

# C: no unwinding at all, status codes only.
prepare c-no-exceptions
"$(dirname "$0")/rewrite-native-variant.py" "$WORK/c-no-exceptions" no-exceptions
measure c-no-exceptions -DANDROID_STL=none
