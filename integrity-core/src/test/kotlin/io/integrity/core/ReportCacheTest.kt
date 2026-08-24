package io.integrity.core

import com.google.common.truth.Truth.assertThat
import kotlin.time.Duration.Companion.seconds
import org.junit.Test

class ReportCacheTest {

    private val cache = ReportCache(mapOf(Depth.QUICK to 10.seconds, Depth.FULL to 60.seconds))
    private val report = IntegrityReport.unknown(Depth.QUICK)

    @Test
    fun `returns a stored report inside its ttl`() {
        cache.put(Depth.QUICK, report, nowMillis = 1_000)

        assertThat(cache.get(Depth.QUICK, nowMillis = 5_000)).isSameInstanceAs(report)
    }

    @Test
    fun `expires a report past its ttl`() {
        cache.put(Depth.QUICK, report, nowMillis = 1_000)

        assertThat(cache.get(Depth.QUICK, nowMillis = 12_000)).isNull()
    }

    @Test
    fun `depths are cached independently`() {
        cache.put(Depth.QUICK, report, nowMillis = 0)

        assertThat(cache.get(Depth.FULL, nowMillis = 0)).isNull()
    }

    @Test
    fun `a depth with no configured ttl is never served from cache`() {
        val noTtl = ReportCache(emptyMap())
        noTtl.put(Depth.FULL, report, nowMillis = 0)

        assertThat(noTtl.get(Depth.FULL, nowMillis = 0)).isNull()
    }

    @Test
    fun `clear drops everything`() {
        cache.put(Depth.QUICK, report, nowMillis = 0)
        cache.clear()

        assertThat(cache.get(Depth.QUICK, nowMillis = 0)).isNull()
    }
}
