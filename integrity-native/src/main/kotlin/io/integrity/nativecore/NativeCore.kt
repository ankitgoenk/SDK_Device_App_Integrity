package io.integrity.nativecore

/** What the native core turned out to be, once we tried to use it. */
internal enum class NativeOutcome {
    /** The host did not ask for a native core. Not a finding. */
    NOT_CONFIGURED,

    /** Expected, but the library would not load. Indistinguishable from a missing ABI. */
    UNAVAILABLE,

    /** Loaded, but a call into it failed. */
    FAILED,

    /** Loaded, but it is not the library this build ships. Positive evidence. */
    LIBRARY_MISMATCH,

    /** Loaded and verified. */
    OK
}

internal interface NativeLibraryLoader {
    fun load(name: String)
}

internal object SystemLibraryLoader : NativeLibraryLoader {
    override fun load(name: String): Unit = System.loadLibrary(name)
}

/** The JNI surface, behind an interface so the states above can be tested off-device. */
internal interface NativeApi {
    fun selfCheck(expectedToken: String): Int
    fun provokeFailure(): Int
}

internal object NativeBridge : NativeApi {

    override fun selfCheck(expectedToken: String): Int = nativeSelfCheck(expectedToken)

    override fun provokeFailure(): Int = nativeProvokeFailure()

    // Registered dynamically in JNI_OnLoad, so the .so exports no Java_* symbol to grep
    // for. CI checks the released library for stray exports rather than trusting this
    // comment (ADR-0002).
    private external fun nativeSelfCheck(expected: String): Int

    private external fun nativeProvokeFailure(): Int
}

/**
 * Loads the native core and establishes which of the [NativeOutcome] states holds.
 *
 * Nothing here may propagate: a native failure inside an SDK embedded in someone else's
 * app must never become that app's crash. For a security SDK, availability is itself a
 * security property.
 */
internal class NativeCore(
    private val expectedByHost: Boolean,
    private val expectedToken: String,
    private val loader: NativeLibraryLoader = SystemLibraryLoader,
    private val api: NativeApi = NativeBridge
) {

    @Suppress("ReturnCount")
    fun evaluate(): NativeOutcome {
        if (!expectedByHost) return NativeOutcome.NOT_CONFIGURED

        val loaded = runCatching { loader.load(LIBRARY_NAME) }.isSuccess
        if (!loaded) return NativeOutcome.UNAVAILABLE

        val code = runCatching { api.selfCheck(expectedToken) }.getOrNull()
            ?: return NativeOutcome.FAILED

        return when (code) {
            STATUS_OK -> NativeOutcome.OK
            STATUS_TOKEN_MISMATCH -> NativeOutcome.LIBRARY_MISMATCH
            else -> NativeOutcome.FAILED
        }
    }

    internal companion object {
        const val LIBRARY_NAME = "integrity"

        // Mirrors integrity::SelfCheckStatus in selfcheck.h.
        const val STATUS_OK = 0
        const val STATUS_TOKEN_MISMATCH = 1
    }
}
