package io.integrity.core

import java.util.EnumMap
import kotlin.time.Duration

/**
 * Per-depth result cache, so a hot path can ask for a verdict without re-running a full
 * sweep. Deliberately in memory only: a report persisted to disk is a report an attacker
 * can replay (docs/PRIVACY_AND_COMPLIANCE.md, P7).
 */
internal class ReportCache(private val ttls: Map<Depth, Duration>) {

    private val entries = EnumMap<Depth, Entry>(Depth::class.java)

    @Synchronized
    fun get(depth: Depth, nowMillis: Long): IntegrityReport? {
        val entry = entries[depth] ?: return null
        val ttl = ttls[depth] ?: return null
        return if (nowMillis - entry.storedAtMillis < ttl.inWholeMilliseconds) entry.report else null
    }

    @Synchronized
    fun put(depth: Depth, report: IntegrityReport, nowMillis: Long) {
        entries[depth] = Entry(report, nowMillis)
    }

    @Synchronized
    fun clear() {
        entries.clear()
    }

    private class Entry(val report: IntegrityReport, val storedAtMillis: Long)
}
