package io.integrity.core

/**
 * Fixtures for the model's own tests.
 *
 * Deliberately a copy of the equivalents in `integrity-core`'s TestDoubles rather than a
 * shared artifact: nine lines of test constants are cheaper than coupling two modules'
 * test suites through a published test-fixtures configuration, and each suite should be
 * readable without opening the other.
 */
internal fun signal(
    id: SignalId,
    category: Category = Category.META,
    confidence: Confidence = Confidence.CONFIRMED
): Signal = Signal(id = id, category = category, confidence = confidence)

internal val ROOT_A = SignalId("ROOT_SU_BINARY")
internal val ROOT_B = SignalId("ROOT_MAGISK_PATHS")
internal val HOOK_A = SignalId("HOOK_FRIDA_MAPS")
internal val ENV_A = SignalId("ENV_ADB_ENABLED")
