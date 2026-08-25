#!/usr/bin/env bash
# Runs ktlint and detekt the way CI runs them.
#
# Written after a session's worth of "detekt: 0 code smells" that meant nothing: the CLI
# was invoked without --build-upon-default-config while build.gradle.kts sets
# buildUponDefaultConfig = true, so every local run used a smaller ruleset than CI and
# passed regardless. A check that cannot fail is not a check.
#
# Usage: tools/run-static-analysis.sh [path ...]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TOOLS="${INTEGRITY_TOOLS:-}"
if [ -z "$TOOLS" ]; then
  echo "Set INTEGRITY_TOOLS to the directory holding ktlint and detekt-cli.jar." >&2
  echo "In a full checkout with the Android SDK, ./gradlew detekt ktlintCheck is the" >&2
  echo "same thing and needs no such directory." >&2
  exit 2
fi

PATHS=("$@")
if [ "${#PATHS[@]}" -eq 0 ]; then
  mapfile -t PATHS < <(find "$ROOT" -maxdepth 2 -name src -type d -not -path '*/build/*' | sort)
fi

echo "=== ktlint ==="
for p in "${PATHS[@]}"; do
  "$TOOLS/ktlint" --relative "$p/**/*.kt" || exit 1
done

echo "=== detekt (buildUponDefaultConfig, matching build.gradle.kts) ==="
joined=$(IFS=,; echo "${PATHS[*]}")
java -jar "$TOOLS/detekt-cli.jar" \
  --config "$ROOT/config/detekt/detekt.yml" \
  --build-upon-default-config \
  --input "$joined"

echo "OK: ktlint and detekt both clean, under the same configuration CI uses."
