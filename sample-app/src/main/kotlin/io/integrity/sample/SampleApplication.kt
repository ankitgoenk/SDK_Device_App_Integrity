package io.integrity.sample

import android.app.Application
import io.integrity.core.Depth
import io.integrity.core.IntegrityConfig
import io.integrity.core.IntegrityGuard
import io.integrity.core.LogcatSink
import io.integrity.core.Policy
import io.integrity.detector.app.AppDetectors
import io.integrity.detector.emulator.EmulatorDetectors
import io.integrity.detector.environment.EnvironmentDetectors
import io.integrity.detector.hooking.HookDetectors
import io.integrity.detector.root.RootDetectors
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

class SampleApplication : Application() {

    private val appScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    override fun onCreate() {
        super.onCreate()

        IntegrityGuard.initialize(
            this,
            IntegrityConfig.Builder()
                .expectedPackageName(packageName)
                .detectors(
                    RootDetectors.all() +
                        HookDetectors.all() +
                        AppDetectors.all() +
                        EnvironmentDetectors.all() +
                        EmulatorDetectors.all() +
                        HostDetector()
                )
                .policy(Policy.observability())
                .reportSink(LogcatSink())
                .build()
        )

        // Never gate app start on this: the full sweep runs off the critical path and the
        // UI reads whatever is cached. See docs/INTEGRATION.md.
        appScope.launch { IntegrityGuard.evaluate(Depth.FULL) }
    }
}
