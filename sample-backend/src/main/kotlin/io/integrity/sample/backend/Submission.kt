package io.integrity.sample.backend

import io.integrity.core.Depth
import io.integrity.core.Signal
import io.integrity.core.Verdict

/**
 * What the client claims about its own conclusion.
 *
 * Every field here is diagnostics. A compromised client can put anything in them, so consuming
 * any of them in a decision would make the pipeline decorative (ADR-0006, "scoring authority").
 * They are kept because divergence between what the client concluded and what the server
 * concludes is itself interesting telemetry.
 *
 * `coveragePermille` lives *here*, deliberately, and not on [SubmittedReport]. Coverage is a
 * claim about how much of the check surface ran, and the client is exactly the party that
 * benefits from overstating it: a tampered client reporting zero signals and full coverage
 * would otherwise score TRUSTED, because a noisy-OR over an empty signal set is zero risk. The
 * server computes coverage itself from [EvidenceExpectation]. Putting the client's number
 * inside the advisory holder makes it unreachable from the scoring path by construction rather
 * than by anyone remembering.
 */
data class ClientAdvisory(val verdict: Verdict, val riskScore: Int, val coveragePermille: Int)

/**
 * A report as the backend receives it, already parsed.
 *
 * Parsing the canonical wire form is out of scope here: `ReportWire` serialises, and writing a
 * matching parser is transport plumbing that would obscure what this PR is about. Tests build
 * this structure directly.
 */
data class SubmittedReport(
    val challenge: String?,
    val sdkVersion: String,
    val depth: Depth,
    val signals: List<Signal>,
    val generatedAtMillis: Long,
    val clientAdvisory: ClientAdvisory?
)

data class ReportSubmission(
    val sessionId: String,
    val report: SubmittedReport,
    val playIntegrityToken: String?,
    /**
     * An upper bound the client asks for on the resulting decision's life.
     *
     * Honoured only where it is shorter than the server's window. ADR-0006 §5: a client may
     * shorten backend freshness and must never be able to extend it.
     */
    val requestedMaxAgeMillis: Long? = null
)

/**
 * What the server concluded about the device, as distinct from what the app may do.
 *
 * Four states rather than a boolean, because the three non-trusted ones are not the same
 * thing and collapsing them is how absence of evidence becomes permission:
 * [UNAVAILABLE] means we could not tell, [INSUFFICIENT_EVIDENCE] means the client did not
 * send enough to tell, and [COMPROMISED] means we could tell and the answer was bad.
 */
enum class DeviceState { TRUSTED, COMPROMISED, UNAVAILABLE, INSUFFICIENT_EVIDENCE }

/** What the app may do. Separate vocabulary from [DeviceState], on purpose. */
enum class Action { ALLOW, STEP_UP, REVIEW, DENY }

/** Why a decision came out the way it did. Diagnostics, and the reason CI can assert on. */
enum class DecisionReason {
    CHALLENGE_REJECTED,
    EVIDENCE_INCOMPLETE,
    ATTESTATION_UNAVAILABLE,
    ATTESTATION_INVALID,
    REQUEST_HASH_MISMATCH,
    APP_NOT_RECOGNISED,
    DEVICE_NOT_RECOGNISED,
    SIGNALS_INDICATE_COMPROMISE,
    OK
}

data class Decision(
    val action: Action,
    val deviceState: DeviceState,
    val reason: DecisionReason,
    /** The challenge this decision answers. Null only when redemption never succeeded. */
    val challenge: String?,
    val purpose: ChallengePurpose?,
    val expiresAtMillis: Long
)
