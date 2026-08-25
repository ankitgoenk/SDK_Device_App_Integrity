#!/usr/bin/env bash
# Builds and runs the native host suites in one configuration.
#
# The file list lived in four CI steps at once, and adding a source to it duplicated an
# entry in one of them, which only showed up as a multiple-definition link error in CI. One
# list, one place. It also means a local run is the same command CI runs, rather than an
# approximation of it.
#
# Usage: tools/run-native-tests.sh <plain|m32|asan> [test-name ...]
set -euo pipefail

CONFIG="${1:?usage: $0 <plain|m32|asan> [test-name ...]}"
shift
TESTS=("$@")
if [ "${#TESTS[@]}" -eq 0 ]; then
  TESTS=(native_host_test native_property_test)
fi

CPP="$(dirname "$0")/../integrity-native/src/main/cpp"
SOURCES=("$CPP/selfcheck.cpp" "$CPP/maps.cpp" "$CPP/safe_read.cpp" "$CPP/selftext.cpp")
COMMON=(-std=c++17 -Wall -Wextra -Werror -fno-exceptions
        -DINTEGRITY_BUILD_TOKEN='"ci-host-token"')

case "$CONFIG" in
  plain) EXTRA=() ;;
  m32)   EXTRA=(-m32) ;;
  asan)  EXTRA=(-fsanitize=address -g) ;;
  *) echo "unknown configuration: $CONFIG" >&2; exit 2 ;;
esac

for test in "${TESTS[@]}"; do
  binary="/tmp/native_${test}_${CONFIG}"
  g++ "${EXTRA[@]}" "${COMMON[@]}" "${SOURCES[@]}" "$CPP/test/$test.cpp" -o "$binary"
  echo "--- $test ($CONFIG)"
  "$binary"
done
