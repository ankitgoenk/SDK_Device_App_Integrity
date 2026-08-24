// Native core — phase 3.
//
// Owns the checks that are not credible in Java, because the JVM layer is exactly what
// Frida and LSPosed control: /proc scanning, thread and module enumeration, function
// prologue and PLT/GOT verification, memory fingerprinting, property probing, digest
// verification, the obfuscated string vault, and report signing. See ADR-0002.
//
// Rules for everything added to this file:
//   * never abort() or throw across the JNI boundary — a native crash is a host-app crash;
//   * bound every read (streamed, 1 MB cap) and fuzz every parser in CI;
//   * prefer raw syscalls over libc wrappers in the critical probes, so a PLT hook on
//     libc does not silently blind us;
//   * no plaintext artefact strings — they come from the build-time vault.

#include <jni.h>

namespace {

/** Placeholder self-check. Phase 3 replaces this with the real entry point. */
jint selfCheck(JNIEnv*, jobject) {
    return 0;
}

const JNINativeMethod kMethods[] = {
        {"nativeSelfCheck", "()I", reinterpret_cast<void*>(selfCheck)},
};

}  // namespace

// Dynamic registration: no exported Java_io_integrity_* symbol to grep for.
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    jclass clazz = env->FindClass("io/integrity/nativecore/NativeBridge");
    if (clazz == nullptr) {
        return JNI_ERR;
    }

    const int count = sizeof(kMethods) / sizeof(kMethods[0]);
    if (env->RegisterNatives(clazz, kMethods, count) != JNI_OK) {
        return JNI_ERR;
    }

    return JNI_VERSION_1_6;
}
