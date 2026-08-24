package io.integrity.consumer

import android.app.Application
import io.integrity.core.IntegrityConfig
import io.integrity.core.IntegrityGuard
import io.integrity.detector.environment.EnvironmentDetectors
import io.integrity.detector.root.RootDetectors
import io.integrity.nativecore.NativeDetectors

/**
 * Stands in for a real integrator: depends on published AARs and follows the
 * documented integration in docs/INTEGRATION.md, nothing more.
 */
class ConsumerApplication : Application() {

    override fun onCreate() {
        super.onCreate()

        IntegrityGuard.initialize(
            this,
            IntegrityConfig.Builder()
                .expectedPackageName(packageName)
                .detectors(RootDetectors.all() + EnvironmentDetectors.all() + NativeDetectors.all())
                .build()
        )
    }
}
