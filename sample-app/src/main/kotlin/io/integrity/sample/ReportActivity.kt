package io.integrity.sample

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import io.integrity.core.Depth
import io.integrity.core.IntegrityGuard
import io.integrity.core.IntegrityReport
import kotlinx.coroutines.launch

/** Renders the current report. Deliberately boring: this is a test surface, not a demo. */
class ReportActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    ReportScreen()
                }
            }
        }
    }
}

@Composable
private fun ReportScreen() {
    val scope = rememberCoroutineScope()
    var report by remember { mutableStateOf(IntegrityGuard.currentReport()) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(text = "Verdict: ${report.verdict}", style = MaterialTheme.typography.headlineSmall)
        Text(text = "Risk score: ${report.riskScore}/100")
        Text(text = "Coverage: ${(report.coverage * 100).toInt()}%")
        Text(text = "Depth: ${report.depth}")
        Text(text = "SDK: ${report.sdkVersion}")
        Text(text = "Report id: ${report.reportId}")

        Text(text = "Signals (${report.signals.size})", style = MaterialTheme.typography.titleMedium)
        if (report.signals.isEmpty()) {
            Text(text = "No signals — detectors land in phases 2-7 (see docs/PLAN.md).")
        } else {
            report.signals.forEach { signal ->
                Text(text = "• ${signal.id} [${signal.category}/${signal.confidence}] ${signal.evidence}")
            }
        }

        Depth.entries.forEach { depth ->
            Button(onClick = {
                scope.launch { report = evaluate(depth) }
            }) {
                Text(text = "Evaluate $depth")
            }
        }
    }
}

private suspend fun evaluate(depth: Depth): IntegrityReport =
    IntegrityGuard.evaluate(depth = depth, force = true)
