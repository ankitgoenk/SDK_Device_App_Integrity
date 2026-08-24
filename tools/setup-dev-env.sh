#!/usr/bin/env bash
# Prepares a clean clone (or a fresh Claude Code web session) to build this project.
# Safe to re-run; prints what is missing rather than failing the session.
set -uo pipefail

ok()   { printf '  \033[32m✓\033[0m %s\n' "$1"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$1"; }

echo "integrity-sdk dev environment"

# --- JDK ---------------------------------------------------------------------
if command -v java >/dev/null 2>&1; then
  version=$(java -version 2>&1 | grep -iE '(openjdk|java) version' | head -1)
  ok "java: $version"
else
  warn "java not found — install a JDK 17 or newer"
fi

# --- Android SDK -------------------------------------------------------------
sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
if [ -n "$sdk" ] && [ -d "$sdk/platforms" ]; then
  ok "android sdk: $sdk"
else
  warn "ANDROID_HOME not set or has no platforms/ — Android modules will not configure."
  warn "  Install cmdline-tools, then:"
  warn "    sdkmanager 'platform-tools' 'platforms;android-35' 'build-tools;35.0.0'"
  warn "  The NDK is only needed once integrity.enableNative=true (phase 3):"
  warn "    sdkmanager 'ndk;27.0.12077973' 'cmake;3.22.1'"
fi

# --- Network -----------------------------------------------------------------
# AGP, AndroidX, Compose and the SDK installer are all served from dl.google.com.
# Restricted-egress environments must allow it or nothing Android will resolve.
if curl -o /dev/null -sS --max-time 15 "https://dl.google.com/dl/android/maven2/" 2>/dev/null; then
  ok "dl.google.com reachable"
else
  warn "dl.google.com unreachable — AGP/AndroidX/Compose cannot resolve."
  warn "  In a restricted-egress sandbox, allow dl.google.com before building."
fi

# --- Gradle ------------------------------------------------------------------
if [ -x ./gradlew ]; then
  ok "gradle wrapper present"
else
  warn "./gradlew missing — run: gradle wrapper"
fi

echo
echo "Build:   ./gradlew build"
echo "Checks:  ./gradlew detekt ktlintCheck apiCheck && tools/check-signal-catalog.py"
