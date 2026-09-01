package io.integrity.sample

import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.integrity.core.Confidence
import io.integrity.core.Depth
import io.integrity.core.IntegrityDiagnostics
import io.integrity.core.IntegrityGuard
import io.integrity.core.IntegrityReport
import io.integrity.core.RunOutcome
import io.integrity.core.Signal
import kotlinx.coroutines.launch

/**
 * The demonstration surface.
 *
 * It has one job beyond showing the report, and that job drives the layout: a viewer must not
 * leave believing the device is clean. On a rooted phone this screen shows a `CONFIRMED` root
 * finding above a verdict of `NO_EVIDENCE_OF_COMPROMISE` and a score of `0/100`, which reads as
 * a contradiction until you know that every signal ships at `INFORMATIONAL` weight (hard rule
 * 6). So the explanation sits next to the number rather than in documentation.
 */
class ReportActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                // Without this the title draws under the status bar on edge-to-edge devices.
                Surface(modifier = Modifier.fillMaxSize().safeDrawingPadding()) { ReportScreen() }
            }
        }
    }
}

/**
 * Palette.
 *
 * `MagicNumber` is suppressed once for the object rather than per constant: an ARGB literal
 * named `CONFIRMED_RED_HEX` adds indirection and no information.
 */
@Suppress("MagicNumber")
private object Palette {
    val confirmed = Color(0xFFB3261E)
    val likely = Color(0xFF8A5A00)
    val muted = Color(0xFF5F6368)
    val evidenceBg = Color(0xFFFCEEEE)
    val neutralBg = Color(0xFFF4F5F7)
}

@Composable
private fun ReportScreen() {
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    var report by remember { mutableStateOf(IntegrityGuard.currentReport()) }
    var busy by remember { mutableStateOf(false) }

    // The Application starts a sweep off the critical path, so the first composition can land
    // before it finishes and render the not-initialized placeholder — "UNKNOWN 0/100" with a
    // META_CONFIG_INVALID signal, which is the worst possible first impression and says nothing
    // about the device. Run a full pass on entry so the screen always shows a real result.
    LaunchedEffect(Unit) {
        busy = true
        report = IntegrityGuard.evaluate(depth = Depth.FULL, force = true)
        busy = false
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp, vertical = 20.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        Text(
            text = "Device & App Integrity",
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.SemiBold
        )
        DeviceCard(report)
        FindingsCard(report)
        VerdictCard(report)
        DiagnosticsCard(DiagnosticsStore.latest(), context)

        HorizontalDivider()
        DepthChooser(
            current = report.depth,
            busy = busy,
            diagnostics = DiagnosticsStore.latest(),
            onPick = { depth ->
                busy = true
                scope.launch {
                    report = IntegrityGuard.evaluate(depth = depth, force = true)
                    busy = false
                }
            }
        )
    }
}

@Composable
private fun DeviceCard(report: IntegrityReport) {
    Card(colors = CardDefaults.cardColors(containerColor = Palette.neutralBg)) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(
                text = "${Build.MANUFACTURER} ${Build.MODEL}",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold
            )
            Text(
                text = "Android ${Build.VERSION.RELEASE} · API ${Build.VERSION.SDK_INT} · " +
                    "SDK ${report.sdkVersion} · depth ${report.depth}",
                style = MaterialTheme.typography.bodySmall,
                color = Palette.muted
            )
        }
    }
}

/** Findings first: this is the only part of the screen that is evidence. */
@Composable
private fun FindingsCard(report: IntegrityReport) {
    val evidence = report.signals.filter { it.confidence != Confidence.INCONCLUSIVE }
    val unresolved = report.signals.filter { it.confidence == Confidence.INCONCLUSIVE }

    Card(
        colors = CardDefaults.cardColors(
            containerColor = if (evidence.isEmpty()) Palette.neutralBg else Palette.evidenceBg
        )
    ) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(
                text = if (evidence.isEmpty()) {
                    "No evidence found"
                } else {
                    "Evidence found (${evidence.size})"
                },
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
                color = if (evidence.isEmpty()) Palette.muted else Palette.confirmed
            )
            if (evidence.isEmpty()) {
                Text(
                    text = "Nothing was observed. That is not the same as the device being " +
                        "clean — a compromise that hides successfully produces this result too.",
                    style = MaterialTheme.typography.bodySmall,
                    color = Palette.muted
                )
            }
            evidence.forEach { SignalRow(it) }

            if (unresolved.isNotEmpty()) {
                HorizontalDivider()
                Text(
                    text = "Could not determine (${unresolved.size})",
                    style = MaterialTheme.typography.titleSmall,
                    color = Palette.muted
                )
                unresolved.forEach { SignalRow(it) }
            }
        }
    }
}

@Composable
private fun SignalRow(signal: Signal) {
    val accent = when (signal.confidence) {
        Confidence.CONFIRMED -> Palette.confirmed
        Confidence.LIKELY -> Palette.likely
        else -> Palette.muted
    }
    Column(verticalArrangement = Arrangement.spacedBy(1.dp)) {
        Row(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = signal.confidence.name,
                style = MaterialTheme.typography.labelSmall,
                fontWeight = FontWeight.Bold,
                color = accent
            )
            Text(
                text = signal.id.toString(),
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.Medium
            )
        }
        Text(
            // Digests are 64 hex characters and wrap into an unreadable block. The prefix is
            // enough to eyeball; the full value is in the shared text and in the report.
            text = signal.evidence.entries.joinToString("  ") { (k, v) ->
                "$k=" + if (v.length > EVIDENCE_VALUE_MAX) v.take(EVIDENCE_VALUE_KEEP) + "…" else v
            },
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
            fontSize = 11.sp,
            color = Palette.muted
        )
    }
}

/**
 * The score, and immediately the reason it is zero.
 *
 * Without the second half this card is actively misleading on a rooted device.
 */
@Composable
private fun VerdictCard(report: IntegrityReport) {
    val hasEvidence = report.signals.any { it.confidence != Confidence.INCONCLUSIVE }
    Card(colors = CardDefaults.cardColors(containerColor = Palette.neutralBg)) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = report.verdict.name.replace('_', ' '),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold
                )
                Text(
                    text = "${report.riskScore}/100",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = Palette.muted
                )
            }
            Text(
                text = "Execution coverage ${(report.coverage * 100).toInt()}% — the share of " +
                    "detectors that reached a conclusion. Not threat coverage.",
                style = MaterialTheme.typography.bodySmall,
                color = Palette.muted
            )
            if (hasEvidence && report.riskScore == 0) {
                HorizontalDivider()
                Text(
                    text = "Why is the score 0 with findings above?",
                    style = MaterialTheme.typography.labelLarge,
                    fontWeight = FontWeight.SemiBold
                )
                Text(
                    text = "Every signal ships at INFORMATIONAL weight until its precision has " +
                        "been measured against real fraud outcomes, so none can move a score " +
                        "yet. The SDK reports what it observed; the backend decides what it is " +
                        "worth. This is deliberate, not an unfinished feature.",
                    style = MaterialTheme.typography.bodySmall,
                    color = Palette.muted
                )
            }
        }
    }
}

/** What ran. Counts first; the uninformative bulk is last and labelled as such. */
@Composable
private fun DiagnosticsCard(diagnostics: IntegrityDiagnostics?, context: Context) {
    if (diagnostics == null) return
    var expanded by remember { mutableStateOf(false) }

    Card(colors = CardDefaults.cardColors(containerColor = Palette.neutralBg)) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(
                text = "Checks run (${diagnostics.runs.size})",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold
            )
            ORDER.forEach { (outcome, label) ->
                val runs = diagnostics.runs.filter { it.outcome == outcome }
                if (runs.isEmpty()) return@forEach
                Row(
                    Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        text = label,
                        style = MaterialTheme.typography.bodyMedium,
                        color = if (outcome == RunOutcome.EMITTED_EVIDENCE) Palette.confirmed else Palette.muted
                    )
                    Text(
                        text = runs.size.toString(),
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Bold,
                        color = Palette.muted
                    )
                }
                if (expanded) {
                    runs.sortedBy { it.detectorId }.forEach { run ->
                        Text(
                            text = "    ${run.detectorId} · " +
                                if (run.durationMillis < 0) "not run" else "${run.durationMillis} ms",
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace,
                            fontSize = 11.sp,
                            color = Palette.muted
                        )
                    }
                }
            }
            Text(
                text = "“Found nothing” means the check saw no evidence. It is not a clean bill " +
                    "of health.",
                style = MaterialTheme.typography.bodySmall,
                color = Palette.muted
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = { expanded = !expanded }) {
                    Text(if (expanded) "Hide detail" else "Show each check")
                }
                Button(onClick = { share(context, diagnostics) }) { Text("Share results") }
            }
        }
    }
}

/**
 * Depth is a cost dial the host turns per call, not a thoroughness setting to leave on maximum.
 *
 * The counts are derived from the diagnostics rather than hardcoded, so this cannot drift from
 * what is actually registered — the failure this project keeps finding in its own documentation.
 */
@Composable
private fun DepthChooser(current: Depth, busy: Boolean, diagnostics: IntegrityDiagnostics?, onPick: (Depth) -> Unit) {
    Text(
        text = "Depth",
        style = MaterialTheme.typography.titleMedium,
        fontWeight = FontWeight.SemiBold
    )
    Text(
        text = "How much work the SDK does. A host would use QUICK at app start, STANDARD at " +
            "login, FULL before a payment.",
        style = MaterialTheme.typography.bodySmall,
        color = Palette.muted
    )
    Depth.entries.forEach { depth ->
        val eligible = diagnostics?.runs?.count { it.minDepth.ordinal <= depth.ordinal }
        Row(
            Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            OutlinedButton(enabled = !busy, onClick = { onPick(depth) }) { Text(depth.name) }
            Column(Modifier.weight(1f)) {
                Text(
                    text = DEPTH_BLURB.getValue(depth),
                    style = MaterialTheme.typography.bodySmall,
                    color = Palette.muted
                )
                Text(
                    text = buildString {
                        append(DEPTH_BUDGET.getValue(depth))
                        if (eligible != null) append("  ·  $eligible detector(s)")
                        if (depth == current) append("  ·  shown above")
                    },
                    style = MaterialTheme.typography.labelSmall,
                    color = if (depth == current) Palette.confirmed else Palette.muted
                )
            }
        }
    }
    if (busy) {
        Text(text = "Running…", style = MaterialTheme.typography.bodySmall, color = Palette.muted)
    }
}

private val DEPTH_BLURB = mapOf(
    Depth.QUICK to "Cached results and constant-time reads only.",
    Depth.STANDARD to "Adds filesystem probes, package queries and JVM hook probes.",
    Depth.FULL to "Adds native scans and digest verification of the app's own code."
)

private val DEPTH_BUDGET = mapOf(
    Depth.QUICK to "target ≤ 20 ms",
    Depth.STANDARD to "target ≤ 150 ms",
    Depth.FULL to "target ≤ 1 s"
)

/** A 64-character digest wraps into an unreadable block; the prefix is enough to eyeball. */
private const val EVIDENCE_VALUE_MAX = 34
private const val EVIDENCE_VALUE_KEEP = 24

private val ORDER = listOf(
    RunOutcome.EMITTED_EVIDENCE to "Found evidence",
    RunOutcome.INCONCLUSIVE to "Could not determine",
    RunOutcome.TIMED_OUT to "Timed out",
    RunOutcome.FAILED to "Failed",
    RunOutcome.FOUND_NOTHING to "Ran, found nothing",
    RunOutcome.SKIPPED_FOR_DEPTH to "Not run at this depth"
)

private fun share(context: Context, diagnostics: IntegrityDiagnostics) {
    val device = "${Build.MANUFACTURER} ${Build.MODEL}, Android ${Build.VERSION.RELEASE} " +
        "(API ${Build.VERSION.SDK_INT})"
    val intent = Intent(Intent.ACTION_SEND).apply {
        type = "text/plain"
        putExtra(Intent.EXTRA_SUBJECT, "Integrity SDK detector run — $device")
        putExtra(Intent.EXTRA_TEXT, DiagnosticsStore.shareText(diagnostics, device))
    }
    context.startActivity(Intent.createChooser(intent, "Share detector results"))
}
