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

#include "safe_read.h"
#include "selfcheck.h"
#include "status.h"

namespace {

constexpr const char* kBridgeClass = "io/integrity/nativecore/NativeBridge";

jint selfCheck(JNIEnv* env, jobject /* thiz */, jstring expected) {
    try {
        if (expected == nullptr) {
            return integrity::kBadArgument;
        }
        const char* chars = env->GetStringUTFChars(expected, nullptr);
        if (chars == nullptr) {
            return integrity::kBadArgument;
        }
        const integrity::SelfCheckStatus status = integrity::verifyBuildToken(chars);
        env->ReleaseStringUTFChars(expected, chars);
        return status;
    } catch (...) {
        // Containment, not diagnosis: the Kotlin side turns this into META_NATIVE_FAILED.
        return integrity::kProvokedFailure;
    }
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

JNINativeMethod methodTable[2] = {
    {const_cast<char*>("nativeSelfCheck"),
     const_cast<char*>("(Ljava/lang/String;)I"),
     reinterpret_cast<void*>(selfCheck)},
    {const_cast<char*>("nativeProbeUnmappedRead"),
     const_cast<char*>("()I"),
     reinterpret_cast<void*>(probeUnmappedRead)},
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
