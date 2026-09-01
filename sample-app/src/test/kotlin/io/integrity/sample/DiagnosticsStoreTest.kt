package io.integrity.sample

import com.google.common.truth.Truth.assertThat
import io.integrity.core.Category
import io.integrity.core.Depth
import io.integrity.core.DetectorRun
import io.integrity.core.IntegrityDiagnostics
import io.integrity.core.RunOutcome
import org.junit.Test

/**
 * The share text is the artefact that leaves the device and reaches a person who was not here.
 * The property worth pinning is not its formatting — it is that the disclaimer cannot be
 * deleted without a test going red.
 */
class DiagnosticsStoreTest {

    private fun run(id: String, outcome: RunOutcome, signals: Int = 0) = DetectorRun(
        detectorId = id,
        category = Category.ROOT,
        minDepth = Depth.QUICK,
        outcome = outcome,
        signalCount = signals,
        durationMillis = 5
    )

    private val diagnostics = IntegrityDiagnostics(
        depth = Depth.FULL,
        reportId = "abc-123",
        sdkVersion = "0.1.0-test",
        runs = listOf(
            run("root.su-binary", RunOutcome.EMITTED_EVIDENCE, signals = 1),
            run("root.prop-spoof", RunOutcome.FOUND_NOTHING),
            run("app.dex-digest", RunOutcome.INCONCLUSIVE, signals = 1),
            run("hooking.deep", RunOutcome.SKIPPED_FOR_DEPTH)
        )
    )

    private val text = DiagnosticsStore.shareText(diagnostics, "Pixel 10a, Android 16")

    @Test
    fun `the disclaimer is present and precedes any result`() {
        // Someone reading a list of green checks concludes the device is clean unless told
        // otherwise, and that conclusion is the one this project cannot allow. If a future
        // edit trims the header for brevity, this fails.
        assertThat(text).contains("NOT a")
        assertThat(text).contains("hides successfully")
        assertThat(text.indexOf("NOT a")).isLessThan(text.indexOf("root.su-binary"))
    }

    @Test
    fun `found nothing is labelled as not a clean result wherever it appears`() {
        assertThat(text).contains("RAN, FOUND NOTHING (not a clean result)")
    }

    @Test
    fun `evidence is listed before the uninformative bulk`() {
        assertThat(text.indexOf("FOUND EVIDENCE")).isLessThan(text.indexOf("RAN, FOUND NOTHING"))
    }

    @Test
    fun `a detector skipped for depth is not reported as having found nothing`() {
        val skipped = text.substringAfter("NOT RUN AT THIS DEPTH")
        assertThat(skipped).contains("hooking.deep")
        assertThat(text.substringAfter("RAN, FOUND NOTHING").substringBefore("NOT RUN"))
            .doesNotContain("hooking.deep")
    }

    @Test
    fun `every detector appears exactly once`() {
        diagnostics.runs.forEach { r ->
            assertThat(text.split(r.detectorId).size - 1).isEqualTo(1)
        }
    }
}
