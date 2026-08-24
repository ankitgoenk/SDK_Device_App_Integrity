package io.integrity.detector.root

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.integrity.core.Confidence
import io.integrity.core.DetectionContext
import io.integrity.core.IntegrityConfig
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The negative control the root family has been missing.
 *
 * Everything so far proves the detectors do not break on a device that is *already*
 * suspicious. This proves the other direction: on a release-keys image with no `su`, they
 * must stay quiet. Without it, "the detectors passed CI" says nothing about whether they
 * can tell a clean device from a compromised one — and that distinction is the whole basis
 * for ever giving these signals real weight.
 *
 * INCONCLUSIVE results are permitted and expected: ROOT_MANAGER_PACKAGE cannot see other
 * packages from this test APK, and reporting that honestly is the designed behaviour.
 * What must not appear is any positive claim about the device.
 */
@RunWith(AndroidJUnit4::class)
@CleanDeviceOnly
class CleanDeviceBaselineTest {

    private class RealDetectionContext(
        override val appContext: Context,
        override val config: IntegrityConfig = IntegrityConfig.Builder().build()
    ) : DetectionContext

    @Test
    fun noRootSignalMakesAPositiveClaimOnACleanImage() = runBlocking {
        val context = RealDetectionContext(ApplicationProvider.getApplicationContext())

        val positives = RootDetectors.all()
            .flatMap { it.detect(context) }
            .filter { it.confidence != Confidence.INCONCLUSIVE }

        assertTrue(
            "clean image produced positive root signals: " +
                positives.joinToString { "${it.id}=${it.confidence}${it.evidence}" },
            positives.isEmpty()
        )
    }
}
