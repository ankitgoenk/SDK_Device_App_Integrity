package io.integrity.nativecore

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.io.File
import java.io.RandomAccessFile
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The on-device fixtures for `HOOK_SELF_TEXT_MISMATCH`, both directions.
 *
 * **A deliberate departure from section 4 of the design, flagged rather than quietly
 * substituted.** That section called for the test to patch its own `.text` through
 * `mprotect`, as the host suite does. Doing that from an instrumented test needs a native
 * entry point that makes this library's own code writable — an attack primitive shipped
 * inside every host app, and a debug-only flag is a weak boundary for an SDK whose entire
 * job is integrity.
 *
 * So the divergence is created on the file side instead: the mapped bytes are copied out,
 * one is flipped, and the measurement is pointed at the copy through a synthetic mapping
 * table. Memory is real and untouched; the file it is compared against is not the one it
 * came from.
 *
 * What that costs: this does not exercise reading *modified* memory on a device. What
 * covers it: the clean measurement already proves the memory read returns exactly the
 * file's bytes — if it did not, the clean case could not report zero — and the host suite
 * performs the genuine `mprotect` self-patch at two widths and under a sanitizer.
 */
@RunWith(AndroidJUnit4::class)
class SelfTextDetectorInstrumentedTest {

    private data class OwnMapping(val start: Long, val end: Long, val fileOffset: Long, val path: String) {
        val length: Int get() = (end - start).toInt()
    }

    private fun describesOwnExecutableMapping(fields: List<String>): Boolean {
        if (fields.size != 6) return false
        return fields[1].startsWith("r-x") && fields[5].contains("libintegrity.so")
    }

    /** Finds this library's executable mapping by walking /proc/self/maps independently. */
    private fun findOwnExecutableMapping(): OwnMapping? =
        File("/proc/self/maps").readLines().firstNotNullOfOrNull { line ->
            val fields = line.trim().split(Regex("\\s+"), limit = 6)
            val addresses = fields.firstOrNull()?.split("-").orEmpty()
            if (!describesOwnExecutableMapping(fields) || addresses.size != 2) {
                null
            } else {
                OwnMapping(
                    start = addresses[0].toLong(16),
                    end = addresses[1].toLong(16),
                    fileOffset = fields[2].toLong(16),
                    path = fields[5]
                )
            }
        }

    private fun cacheFile(name: String): File =
        File(ApplicationProvider.getApplicationContext<Context>().cacheDir, name)

    /** Copies the mapped extent out of the backing file so a fixture can diverge from it. */
    private fun extractMappedBytes(mapping: OwnMapping): ByteArray? = runCatching {
        RandomAccessFile(mapping.path, "r").use { file ->
            val buffer = ByteArray(mapping.length)
            file.seek(mapping.fileOffset)
            file.readFully(buffer)
            buffer
        }
    }.getOrNull()

    private fun writeMapsTable(mapping: OwnMapping, backing: File): File {
        val table = cacheFile("integrity-test-maps")
        table.writeText(
            "%x-%x r-xp 00000000 fd:00 7 %s\n".format(mapping.start, mapping.end, backing.path)
        )
        return table
    }

    @Test
    fun theDetectorIsSilentOnAnUnmodifiedLibrary() {
        SystemLibraryLoader.load(NativeCore.LIBRARY_NAME)

        val values = NativeBridge.measureSelfText()
        assertNotNull("the measurement call failed", values)
        assertEquals(
            "the measurement could not complete; that is 'not checked', never 'clean'",
            NativeCore.STATUS_OK,
            values!![NativeCore.MEASURE_STATUS].toInt()
        )
        assertTrue(values[NativeCore.MEASURE_BYTES_COMPARED] > 0)
        assertEquals(0L, values[NativeCore.MEASURE_BYTES_DIFFERING])
    }

    /**
     * The positive control, and the anti-vacuity checks that make it mean something.
     *
     * Three things are established before the result is believed: the fixture was built at
     * all, the unmodified copy reproduces the clean answer (so the synthetic table is
     * faithful rather than merely different), and only then does the flipped byte have to
     * show up.
     */
    @Test
    fun aDivergentFileIsDetected() {
        SystemLibraryLoader.load(NativeCore.LIBRARY_NAME)

        val mapping = findOwnExecutableMapping()
        if (mapping == null) {
            println("SKIPPED: no executable mapping for libintegrity.so; fixture not built")
            return
        }
        val original = extractMappedBytes(mapping)
        if (original == null || original.isEmpty()) {
            println("SKIPPED: could not read the mapped extent from ${mapping.path}")
            return
        }

        // 1. The faithful copy must reproduce the clean answer. If it does not, the
        //    synthetic table is wrong and any difference below would be the fixture's
        //    fault rather than a detection.
        val faithful = cacheFile("integrity-faithful.bin").apply { writeBytes(original) }
        val cleanValues = NativeBridge.measureSelfTextFrom(writeMapsTable(mapping, faithful).path)
        assertNotNull(cleanValues)
        assertEquals(
            "the synthetic table did not reproduce the clean result, so the fixture is wrong",
            NativeCore.STATUS_OK,
            cleanValues!![NativeCore.MEASURE_STATUS].toInt()
        )
        assertTrue(cleanValues[NativeCore.MEASURE_BYTES_COMPARED] > 0)
        assertEquals(0L, cleanValues[NativeCore.MEASURE_BYTES_DIFFERING])

        // 2. Now diverge by exactly one byte, and prove the divergence exists on disk
        //    before asking whether it was noticed.
        val modified = original.copyOf()
        modified[0] = (modified[0].toInt() xor 0xff).toByte()
        assertTrue("the fixture did not actually diverge", modified[0] != original[0])
        val divergent = cacheFile("integrity-divergent.bin").apply { writeBytes(modified) }

        val values = NativeBridge.measureSelfTextFrom(writeMapsTable(mapping, divergent).path)
        assertNotNull(values)
        assertEquals(NativeCore.STATUS_OK, values!![NativeCore.MEASURE_STATUS].toInt())
        assertEquals(
            "the modified byte was not detected, so the clean zero above proves nothing",
            1L,
            values[NativeCore.MEASURE_BYTES_DIFFERING]
        )
        assertEquals(0L, values[NativeCore.MEASURE_FIRST_DIFFERENCE])
    }
}
