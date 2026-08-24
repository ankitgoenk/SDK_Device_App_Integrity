package io.integrity.core

import android.content.Context
import kotlin.time.Duration
import kotlinx.coroutines.delay

/**
 * A DetectionContext without an Android Context.
 *
 * The engine only passes the context through, so nothing under test touches it. Making
 * the getter throw keeps that honest: if the engine ever starts reaching for a Context,
 * these tests fail loudly rather than quietly needing Robolectric.
 */
internal class FakeDetectionContext(override val config: IntegrityConfig = IntegrityConfig.Builder().build()) :
    DetectionContext {
    override val appContext: Context
        get() = error("appContext must not be touched by the engine")
}

internal class ScriptedDetector(
    override val id: String = "scripted",
    override val category: Category = Category.META,
    override val minDepth: Depth = Depth.QUICK,
    override val budget: Duration = Detector.DEFAULT_BUDGET,
    private val signals: List<Signal> = emptyList(),
    private val stallFor: Duration? = null,
    private val failWith: Throwable? = null
) : Detector {

    var invocations: Int = 0
        private set

    override suspend fun detect(context: DetectionContext): List<Signal> {
        invocations++
        failWith?.let { throw it }
        stallFor?.let { delay(it) }
        return signals
    }
}

internal fun signal(
    id: SignalId,
    category: Category = Category.META,
    confidence: Confidence = Confidence.CONFIRMED
): Signal = Signal(id = id, category = category, confidence = confidence)

internal val ROOT_A = SignalId("ROOT_SU_BINARY")
internal val ROOT_B = SignalId("ROOT_MAGISK_PATHS")
internal val HOOK_A = SignalId("HOOK_FRIDA_MAPS")
internal val ENV_A = SignalId("ENV_ADB_ENABLED")
