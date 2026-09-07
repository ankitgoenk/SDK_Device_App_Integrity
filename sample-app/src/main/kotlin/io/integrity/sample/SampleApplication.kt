package io.integrity.sample

import android.app.Application
import io.integrity.core.Depth
import io.integrity.core.Detector
import io.integrity.core.IntegrityConfig
import io.integrity.core.IntegrityGuard
import io.integrity.core.LogcatSink
import io.integrity.core.Policy
import io.integrity.detector.app.AppDetectors
import io.integrity.detector.emulator.EmulatorDetectors
import io.integrity.detector.environment.EnvironmentDetectors
import io.integrity.detector.hooking.HookDetectors
import io.integrity.detector.root.RootDetectors
import io.integrity.nativecore.NativeDetectors
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
                .detectors(detectors())
                .policy(Policy.observability())
                .reportSink(LogcatSink())
                .diagnosticsSink(DiagnosticsStore::record)
                .build()
        )

        // Never gate app start on this: the full sweep runs off the critical path and the
        // UI reads whatever is cached. See docs/INTEGRATION.md.
        appScope.launch { IntegrityGuard.evaluate(Depth.FULL) }
    }

    internal companion object {
        /**
         * Every detector the sample registers, extracted so the instrumented suite can assert
         * against the real configuration rather than a hand-kept copy of it.
         *
         * `everySignalBelongsToARegisteredCategory` used to compare against a literal
         * `setOf(ROOT, APP_TAMPER, META)`, which was really "categories observed so far". It
         * broke the first time a new family started emitting — `ENVIRONMENT`, when
         * `ENV_NO_DEVICE_LOCK` shipped — and `HOOKING` was the same break waiting for a device
         * with an unexpected module mapped into it.
         */
        fun detectors(): List<Detector> = RootDetectors.all() +
            HookDetectors.all() +
            AppDetectors.all() +
            EnvironmentDetectors.all() +
            EmulatorDetectors.all() +
            NativeDetectors.all() +
            HostDetector()
    }
}
