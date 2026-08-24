package io.integrity.nativecore

/**
 * The single JVM door into the native core.
 *
 * A missing or broken native library is itself a signal: deleting the .so is the laziest
 * bypass there is, so [available] being false must be scored as
 * [io.integrity.core.SignalId.META_NATIVE_UNAVAILABLE], not shrugged off.
 */
public object NativeBridge {

    public val available: Boolean = runCatching {
        System.loadLibrary("integrity")
        nativeSelfCheck() == 0
    }.getOrDefault(false)

    @JvmStatic
    private external fun nativeSelfCheck(): Int
}
