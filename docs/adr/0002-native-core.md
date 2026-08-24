# 0002. A native (C++) core for hooking and code-integrity checks

Date: 2026-08-24
Status: Accepted

## Context

Java/Kotlin detection code runs inside ART, which is exactly the layer that Frida, LSPosed and
friends control. A Kotlin function that reads `/proc/self/maps` through `java.io.File` can be
neutralised by hooking `FileInputStream`, or by hooking the detector method itself to return
an empty list. Java-only anti-hooking is theatre.

Native code is not immune — but the attacker must move from "one Frida script against a named
Kotlin method" to "patch stripped, symbol-less native code with obfuscated constants".

## Decision

`integrity-native` (C++17, NDK) owns: `/proc` scanning, thread/module enumeration, function
prologue and PLT/GOT verification, memory fingerprint scanning, property probing, digest
verification, the obfuscated string vault, and report signing. Built for arm64-v8a,
armeabi-v7a and x86_64. JNI methods registered dynamically in `JNI_OnLoad`; symbols hidden and
stripped. Critical probes use raw syscalls rather than `libc` wrappers.

## Consequences

- **Easier:** materially higher bypass cost; access to information the JVM cannot see;
  signing keys that are not Java constants.
- **Harder:** three ABIs to build and test; native crashes are host-app crashes, so every
  entry point needs wrapping and every parser needs fuzzing; APK size grows (~250 KB/ABI
  budget); NDK toolchain in CI.
- **Accepted:** the JVM layer stays functional if the native library is missing, and its
  absence is itself a scored signal (`META_NATIVE_UNAVAILABLE`).
