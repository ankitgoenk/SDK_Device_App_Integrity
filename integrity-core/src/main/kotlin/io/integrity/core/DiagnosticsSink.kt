package io.integrity.core

/**
 * Receives a description of what the SDK just did, in-process, for humans.
 *
 * Opt-in via [IntegrityConfig.Builder.diagnosticsSink]. Nothing delivered here is evidence:
 * see [IntegrityDiagnostics] for why a list of checks that found nothing must never travel in
 * a report, and [RunOutcome.FOUND_NOTHING] for why the most common outcome says least.
 *
 * Intended for a QA build, a bug report, or a tester running on hardware the team does not own.
 * Do not wire it to a production analytics pipeline expecting a trust signal; there is none here.
 */
public fun interface DiagnosticsSink {
    public fun onDiagnostics(diagnostics: IntegrityDiagnostics)
}
