package io.integrity.detector.environment

import android.content.Context
import com.google.common.truth.Truth.assertThat
import io.integrity.core.Category
import io.integrity.core.Confidence
import io.integrity.core.DetectionContext
import io.integrity.core.IntegrityConfig
import io.integrity.core.SignalId
import kotlinx.coroutines.test.runTest
import org.junit.Test

/**
 * `ENV_NO_DEVICE_LOCK`, and the direction that makes it safe.
 *
 * The interesting assertion is not that an unlocked device produces a signal. It is that a
 * **locked one produces nothing** — because a signal emitted when the device *was* secured
 * would be something in a report that raises trust, which hard rule 9 and ADR-0007 forbid.
 * A detector of device *posture* is the easiest place in this catalogue to get that backwards,
 * since the natural phrasing is "report whether the device is locked".
 */
class DeviceLockDetectorTest {

    private class FakeLock(private val secure: Boolean?) : DeviceLockProbe {
        override fun isDeviceSecure(): Boolean? = secure
    }

    // The detector never touches appContext when a probe is injected; `Context` is only needed
    // to satisfy the interface, and Android's unit-test stubs return a usable no-op.
    private val context = object : DetectionContext {
        override val appContext: Context get() = error("not reached: the probe is injected")
        override val config: IntegrityConfig = IntegrityConfig.Builder().build()
    }

    private suspend fun detect(secure: Boolean?) = DeviceLockDetector(FakeLock(secure)).detect(context)

    @Test
    fun `an unsecured device is reported, confirmed`() = runTest {
        val signals = detect(secure = false)

        assertThat(signals).hasSize(1)
        assertThat(signals.single().id).isEqualTo(SignalId.ENV_NO_DEVICE_LOCK)
        assertThat(signals.single().confidence).isEqualTo(Confidence.CONFIRMED)
        assertThat(signals.single().category).isEqualTo(Category.ENVIRONMENT)
    }

    @Test
    fun `a secured device produces no signal at all`() {
        // The load-bearing one. Not "produces a signal saying it is fine" -- nothing. Evidence
        // can incriminate and can never exonerate, so there is no value this detector can emit
        // that a backend could read as a lock screen being present.
        runTest {
            assertThat(detect(secure = true)).isEmpty()
        }
    }

    @Test
    fun `an unreadable keyguard is inconclusive rather than silent`() = runTest {
        // Hard rule 2. "Could not check" and "checked and found a lock screen" are the same
        // silence to anyone counting signals, so the first has to say so out loud.
        val signals = detect(secure = null)

        assertThat(signals).hasSize(1)
        assertThat(signals.single().confidence).isEqualTo(Confidence.INCONCLUSIVE)
        assertThat(signals.single().evidence["reason"]).isEqualTo("keyguard_unavailable")
    }

    @Test
    fun `evidence carries nothing about the person using the device`() {
        // Privacy rules P1-P5. The finding is its own content; anything further would be
        // describing someone's security habits rather than a device fact.
        runTest {
            assertThat(detect(secure = false).single().evidence).isEmpty()
        }
    }

    @Test
    fun `the three outcomes are distinguishable`() = runTest {
        // Guards against the collapse that makes the suite above vacuous: a detector returning
        // the same thing for every input would satisfy any two of these assertions in isolation.
        val unsecured = detect(secure = false)
        val secured = detect(secure = true)
        val unknown = detect(secure = null)

        assertThat(unsecured).isNotEqualTo(secured)
        assertThat(unsecured).isNotEqualTo(unknown)
        assertThat(secured).isNotEqualTo(unknown)
    }
}
