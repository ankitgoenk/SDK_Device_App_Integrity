package io.integrity.detector.root

import android.content.Context
import android.os.Build
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.integrity.core.Confidence
import io.integrity.core.DetectionContext
import io.integrity.core.IntegrityConfig
import io.integrity.core.SignalId
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The positive control the root family has been missing, and the reason the gap was
 * invisible: this module's only instrumented test was `@CleanDeviceOnly`, which the
 * rooted-image job filters out. That job therefore ran zero root tests while reporting
 * success — a negative control with no positive one, which is the same missing direction
 * the native read path had.
 *
 * `CleanDeviceBaselineTest` proves the detectors stay quiet on a clean image. On its own
 * that is satisfied perfectly by a detector that is quiet everywhere, including on a
 * device shipping `su`. Both directions are needed before these signals mean anything.
 *
 * Runs on `google_apis`, a userdebug image reporting `test-keys`. Not annotated
 * `@CleanDeviceOnly`, so the rooted-image job picks it up and the clean-baseline job does
 * not.
 */
@RunWith(AndroidJUnit4::class)
class RootedImagePositiveControlTest {

    private class RealDetectionContext(
        override val appContext: Context,
        override val config: IntegrityConfig = IntegrityConfig.Builder().build()
    ) : DetectionContext

    /**
     * Establishes the fixture before anything is concluded from it.
     *
     * Without this, a CI image swapped to release-keys would make the detectors correctly
     * fall silent, and the assertion below would fail as though the detectors had broken.
     * The failure message needs to say "the rooted fixture is gone", not "root detection
     * regressed", or the next person spends a day debugging working code.
     */
    @Test
    fun theImageUnderTestIsActuallyARootedOne() {
        val tags = Build.TAGS.orEmpty()
        val type = Build.TYPE.orEmpty()

        assertTrue(
            "fixture missing: expected a test-keys or userdebug image, got tags='$tags' type='$type'. " +
                "The rooted-image job must run on google_apis, not google_apis_playstore.",
            tags.contains("test-keys") || type == "userdebug" || type == "eng"
        )
    }

    /**
     * The deterministic half: a `test-keys` / userdebug image is exactly what
     * ROOT_DANGEROUS_PROPS reads, so this cannot depend on emulator specifics the way
     * probing for an `su` binary readable at app UID would.
     */
    @Test
    fun theBuildPropertiesDetectorFiresOnATestKeysImage() = runBlocking {
        val context = RealDetectionContext(ApplicationProvider.getApplicationContext())

        // Reached through RootDetectors rather than by instantiating the detector, which
        // is internal: this asserts the property of the family as it is actually wired,
        // and does not depend on androidTest keeping friend access to the main source set.
        val signal = RootDetectors.all().flatMap { it.detect(context) }
            .singleOrNull { it.id == SignalId.ROOT_DANGEROUS_PROPS }

        assertTrue(
            "ROOT_DANGEROUS_PROPS produced no signal on a test-keys image",
            signal != null
        )
        assertEquals(
            "a test-keys image must be a positive claim, not an inconclusive one",
            Confidence.POSSIBLE,
            signal?.confidence
        )
    }

    /**
     * The family-level property: on an image that advertises itself as modified, the root
     * detectors as a group must make at least one positive claim. INCONCLUSIVE is a
     * legitimate answer for individual detectors here — ROOT_MANAGER_PACKAGE cannot see
     * other packages from this APK — but if *every* detector lands there, the family has
     * told us nothing about a device we know is suspicious.
     */
    @Test
    fun theRootFamilyMakesAtLeastOnePositiveClaim() = runBlocking {
        val context = RealDetectionContext(ApplicationProvider.getApplicationContext())

        val signals = RootDetectors.all().flatMap { it.detect(context) }
        val positives = signals.filter { it.confidence != Confidence.INCONCLUSIVE }

        assertTrue(
            "no root detector made a positive claim on a rooted image; all signals were: " +
                signals.joinToString { "${it.id}=${it.confidence}" },
            positives.isNotEmpty()
        )
    }
}
