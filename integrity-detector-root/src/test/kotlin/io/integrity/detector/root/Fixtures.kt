package io.integrity.detector.root

import android.content.Context
import io.integrity.core.DetectionContext
import io.integrity.core.IntegrityConfig

/**
 * Fixtures standing in for device state. Real rooted-device runs are the instrumented
 * tests' job; these pin the decision logic so a regression shows up in seconds.
 */
internal class FakeFileProbe(private val present: Set<String>) : FileProbe {
    override fun exists(path: String): Boolean = path in present
}

internal class FakePackageProbe(
    private val installed: Set<String> = emptySet(),
    override val absenceIsConclusive: Boolean = true
) : PackageProbe {
    override fun isInstalled(packageName: String): Boolean = packageName in installed
}

internal class FakeBuildProbe(override val tags: String? = "release-keys", override val type: String? = "user") :
    BuildProbe

internal class FakeDetectionContext(override val config: IntegrityConfig = IntegrityConfig.Builder().build()) :
    DetectionContext {
    override val appContext: Context
        get() = error("a unit test must not need a real Context")
}

/** A stock device: nothing interesting on disk. */
internal val CLEAN_FILES = FakeFileProbe(emptySet())
