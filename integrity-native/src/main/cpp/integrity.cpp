// JNI boundary for the native core.
//
// Phase 3a: this ships one real check (the build token) and nothing else. Prologue and
// GOT verification, memory fingerprints and the string vault come in phase 3b, once this
// skeleton has proven it can be delivered to a device safely. See docs/PLAN.md.
//
// Rules for everything added here:
//   * never let anything escape this boundary — a native crash is a host-app crash, and
//     for an SDK embedded in someone else's app that is worse than a missed detection;
//   * never abort();
//   * no exported Java_* symbols: methods are registered dynamically in JNI_OnLoad, and
//     CI checks the released .so for stray exports.

#include <jni.h>
#include <stddef.h>

#include "safe_read.h"
#include "selfcheck.h"
#include "status.h"

namespace {

constexpr const char* kBridgeClass = "io/integrity/nativecore/NativeBridge";

jint selfCheck(JNIEnv* env, jobject /* thiz */, jstring expected) {
    if (expected == nullptr) {
        return integrity::kBadArgument;
    }
    // A null return here means the VM has a pending OutOfMemoryError. It is a Java
    // exception, not a C++ one, so no catch block ever saw it: it propagates when this
    // frame returns and NativeCore's runCatching turns it into NativeOutcome.FAILED.
    const char* chars = env->GetStringUTFChars(expected, nullptr);
    if (chars == nullptr) {
        return integrity::kBadArgument;
    }
    const integrity::SelfCheckStatus status = integrity::verifyBuildToken(chars);
    env->ReleaseStringUTFChars(expected, chars);
    return status;
}

/**
 * Attempts a read of an address that is never mapped, and reports what happened.
 *
 * Replaces a hook that threw an exception purely so a test could watch it be caught, which
 * proved a property of the test hook. This exercises the real production read path and
 * proves the property that matters: a bad address becomes a status code rather than a
 * signal. It is also how ADR-0005's flagged assumption about /proc/self/mem gets confirmed
 * on real devices rather than assumed.
 */
jint probeUnmappedRead(JNIEnv* /* env */, jobject /* thiz */) {
    unsigned char scratch[16];
    constexpr uintptr_t kNeverMapped = 0xdead0000u;
    return integrity::readSelfMemory(kNeverMapped, scratch, sizeof(scratch));
}

// A read target inside this library. Sized so the probe's whole extent lies within one
// object: reading past the end of a short string could cross into an unmapped page and
// report a failure that was really the test's fault.
const unsigned char kMappedProbeTarget[16] = {
    0x49, 0x4e, 0x54, 0x45, 0x47, 0x52, 0x49, 0x54,
    0x59, 0x2d, 0x50, 0x52, 0x4f, 0x42, 0x45, 0x00,
};

/**
 * Reads an address that certainly *is* mapped, and reports what happened.
 *
 * The counterpart to probeUnmappedRead, and it exists because that one alone cannot tell
 * a working read path from a broken one: an implementation that returned
 * kStatusUnavailable for every address would satisfy it perfectly. off_t truncation on
 * 32-bit ABIs did exactly that, and every test stayed green (ADR-0005 point 3b).
 *
 * So this asserts the positive direction, and checks the bytes rather than only the
 * status: a read that reports success while copying nothing is the same collapse wearing
 * a different hat.
 */
jint probeMappedRead(JNIEnv* /* env */, jobject /* thiz */) {
    unsigned char scratch[sizeof(kMappedProbeTarget)] = {0};
    const uintptr_t address = reinterpret_cast<uintptr_t>(kMappedProbeTarget);

    const integrity::NativeStatus status =
        integrity::readSelfMemory(address, scratch, sizeof(scratch));
    if (status != integrity::kStatusOk) {
        return status;
    }

    for (size_t i = 0; i < sizeof(scratch); ++i) {
        if (scratch[i] != kMappedProbeTarget[i]) {
            return integrity::kStatusInternalError;
        }
    }
    return integrity::kStatusOk;
}

JNINativeMethod methodTable[3] = {
    {const_cast<char*>("nativeSelfCheck"),
     const_cast<char*>("(Ljava/lang/String;)I"),
     reinterpret_cast<void*>(selfCheck)},
    {const_cast<char*>("nativeProbeUnmappedRead"),
     const_cast<char*>("()I"),
     reinterpret_cast<void*>(probeUnmappedRead)},
    {const_cast<char*>("nativeProbeMappedRead"),
     const_cast<char*>("()I"),
     reinterpret_cast<void*>(probeMappedRead)},
};

}  // namespace

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* /* reserved */) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    jclass clazz = env->FindClass(kBridgeClass);
    if (clazz == nullptr) {
        return JNI_ERR;
    }

    const int count = static_cast<int>(sizeof(methodTable) / sizeof(methodTable[0]));
    if (env->RegisterNatives(clazz, methodTable, count) != JNI_OK) {
        return JNI_ERR;
    }

    return JNI_VERSION_1_6;
}
