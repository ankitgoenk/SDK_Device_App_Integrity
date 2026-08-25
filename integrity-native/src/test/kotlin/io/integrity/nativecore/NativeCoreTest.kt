package io.integrity.nativecore

import android.content.Context
import com.google.common.truth.Truth.assertThat
import io.integrity.core.Category
import io.integrity.core.Confidence
import io.integrity.core.DetectionContext
import io.integrity.core.IntegrityConfig
import io.integrity.core.SignalId
import kotlinx.coroutines.test.runTest
import org.junit.Test

private const val TOKEN = "0.1.0-test"

private class FakeLoader(private val fails: Boolean = false) : NativeLibraryLoader {
    override fun load(name: String) {
        if (fails) throw UnsatisfiedLinkError("no $name for this ABI")
    }
}

private class FakeApi(private val status: Int = NativeCore.STATUS_OK, private val throws: Boolean = false) :
    NativeApi {
    override fun selfCheck(expectedToken: String): Int {
        if (throws) error("native call blew up")
        return status
    }

    override fun probeUnmappedRead(): Int = NativeCore.STATUS_UNAVAILABLE

    override fun probeMappedRead(): Int = NativeCore.STATUS_OK

    override fun measureSelfText(): LongArray? = longArrayOf(0, 1, 4096, 0, 0)
}

private class FakeDetectionContext : DetectionContext {
    override val config: IntegrityConfig = IntegrityConfig.Builder().build()
    override val appContext: Context
        get() = error("a unit test must not need a real Context")
}

/**
 * The state matrix as a contract, off-device.
 *
 * Each row is a different reason the native core might not be usable, and they must not
 * collapse into one another: "the SDK could not run" and "the device is compromised" are
 * different observations, and only one of them is evidence.
 */
class NativeCoreTest {

    private fun core(
        expected: Boolean = true,
        loaderFails: Boolean = false,
        status: Int = NativeCore.STATUS_OK,
        apiThrows: Boolean = false
    ) = NativeCore(
        expectedByHost = expected,
        expectedToken = TOKEN,
        loader = FakeLoader(loaderFails),
        api = FakeApi(status, apiThrows)
    )

    @Test
    fun `native disabled by the host is not configured`() {
        assertThat(core(expected = false).evaluate()).isEqualTo(NativeOutcome.NOT_CONFIGURED)
    }

    @Test
    fun `expected but unloadable is unavailable`() {
        assertThat(core(loaderFails = true).evaluate()).isEqualTo(NativeOutcome.UNAVAILABLE)
    }

    @Test
    fun `loaded but the call throws is failed`() {
        assertThat(core(apiThrows = true).evaluate()).isEqualTo(NativeOutcome.FAILED)
    }

    @Test
    fun `loaded but an unknown status is failed`() {
        assertThat(core(status = 99).evaluate()).isEqualTo(NativeOutcome.FAILED)
    }

    @Test
    fun `loaded with a token mismatch is a library mismatch`() {
        assertThat(core(status = NativeCore.STATUS_TOKEN_MISMATCH).evaluate())
            .isEqualTo(NativeOutcome.LIBRARY_MISMATCH)
    }

    @Test
    fun `loaded and verified is ok`() {
        assertThat(core().evaluate()).isEqualTo(NativeOutcome.OK)
    }

    @Test
    fun `a load failure never propagates to the caller`() {
        // The host app must not crash because our library is missing.
        assertThat(core(loaderFails = true).evaluate()).isEqualTo(NativeOutcome.UNAVAILABLE)
        assertThat(core(apiThrows = true).evaluate()).isEqualTo(NativeOutcome.FAILED)
    }
}

class NativeIntegrityDetectorTest {

    private suspend fun detect(
        expected: Boolean = true,
        loaderFails: Boolean = false,
        status: Int = NativeCore.STATUS_OK,
        apiThrows: Boolean = false
    ) = NativeIntegrityDetector(
        NativeCore(
            expectedByHost = expected,
            expectedToken = TOKEN,
            loader = FakeLoader(loaderFails),
            api = FakeApi(status, apiThrows)
        )
    ).detect(FakeDetectionContext())

    @Test
    fun `a healthy native core produces no signal`() = runTest {
        assertThat(detect()).isEmpty()
    }

    @Test
    fun `not configured is meta and inconclusive`() = runTest {
        val signal = detect(expected = false).single()

        assertThat(signal.id).isEqualTo(SignalId.META_NATIVE_NOT_CONFIGURED)
        assertThat(signal.category).isEqualTo(Category.META)
        assertThat(signal.confidence).isEqualTo(Confidence.INCONCLUSIVE)
    }

    @Test
    fun `unavailable is inconclusive, because deletion looks like a missing ABI`() = runTest {
        val signal = detect(loaderFails = true).single()

        assertThat(signal.id).isEqualTo(SignalId.META_NATIVE_UNAVAILABLE)
        assertThat(signal.category).isEqualTo(Category.META)
        assertThat(signal.confidence).isEqualTo(Confidence.INCONCLUSIVE)
    }

    @Test
    fun `a failed call is meta and inconclusive`() = runTest {
        val signal = detect(apiThrows = true).single()

        assertThat(signal.id).isEqualTo(SignalId.META_NATIVE_FAILED)
        assertThat(signal.confidence).isEqualTo(Confidence.INCONCLUSIVE)
    }

    @Test
    fun `a library mismatch is the only state that accuses the device`() = runTest {
        val signal = detect(status = NativeCore.STATUS_TOKEN_MISMATCH).single()

        assertThat(signal.id).isEqualTo(SignalId.APP_NATIVE_LIB_MISMATCH)
        assertThat(signal.category).isEqualTo(Category.APP_TAMPER)
        assertThat(signal.confidence).isEqualTo(Confidence.CONFIRMED)
    }

    @Test
    fun `no state reports the build token`() = runTest {
        val states = listOf(
            detect(expected = false),
            detect(loaderFails = true),
            detect(apiThrows = true),
            detect(status = NativeCore.STATUS_TOKEN_MISMATCH)
        ).flatten()

        states.forEach { signal ->
            assertThat(signal.evidence.values.none { it.contains(TOKEN) }).isTrue()
        }
    }

    @Test
    fun `every native state ships informational`() {
        val policy = io.integrity.core.Policy.balanced()
        val informational = io.integrity.core.Weight.INFORMATIONAL

        assertThat(policy.weightOf(SignalId.META_NATIVE_NOT_CONFIGURED)).isEqualTo(informational)
        assertThat(policy.weightOf(SignalId.META_NATIVE_UNAVAILABLE)).isEqualTo(informational)
        assertThat(policy.weightOf(SignalId.META_NATIVE_FAILED)).isEqualTo(informational)
        assertThat(policy.weightOf(SignalId.APP_NATIVE_LIB_MISMATCH)).isEqualTo(informational)
    }
}
