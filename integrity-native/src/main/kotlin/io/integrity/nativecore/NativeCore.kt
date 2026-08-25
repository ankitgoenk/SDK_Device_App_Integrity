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

    /**
     * Reads an address that is never mapped, returning the status it produced.
     *
     * Exercises the production read path rather than a test hook, and is how ADR-0005's
     * /proc/self/mem assumption is confirmed on a real device.
     */
    fun probeUnmappedRead(): Int

    /**
     * Reads an address that certainly is mapped, returning the status it produced.
     *
     * The counterpart to [probeUnmappedRead]. On its own that one cannot distinguish a
     * working read path from one that fails for everything, which is exactly the collapse
     * `off_t` truncation caused on 32-bit ABIs. See CONTRIBUTING.md, "Testing around the
     * 'couldn't verify' state".
     */
    fun probeMappedRead(): Int
}

internal object NativeBridge : NativeApi {

    override fun selfCheck(expectedToken: String): Int = nativeSelfCheck(expectedToken)

    override fun probeUnmappedRead(): Int = nativeProbeUnmappedRead()

    override fun probeMappedRead(): Int = nativeProbeMappedRead()

    // Registered dynamically in JNI_OnLoad, so the .so exports no Java_* symbol to grep
    // for. CI checks the released library for stray exports rather than trusting this
    // comment (ADR-0002).
    private external fun nativeSelfCheck(expected: String): Int

    private external fun nativeProbeUnmappedRead(): Int

    private external fun nativeProbeMappedRead(): Int
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

        // Mirrors integrity::NativeStatus in status.h. Deliberately disjoint from the
        // values above so a confusion between the two shows up as an obviously wrong
        // number rather than a plausible one.
        const val STATUS_UNAVAILABLE = 11
        const val STATUS_INTERNAL_ERROR = 13
    }
}
