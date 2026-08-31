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
 * benefits from overstating it. The server does not recompute coverage either — ADR-0007
 * settled that it cannot, because a detector that finds nothing emits no signal — so the
 * number has no honest consumer anywhere. Putting it inside the advisory holder makes it
 * unreachable from the scoring path by construction rather than by anyone remembering.
 */
data class ClientAdvisory(val verdict: Verdict, val riskScore: Int, val coveragePermille: Int)

/**
 * A report as the backend receives it, already parsed.
 *
 * [SubmittedReports.fromCanonicalJson] builds one from the wire form, using the parser in
 * `integrity-model` so that both ends of the format are one implementation. Tests may also
 * build this structure directly, which is why it stays a plain data class.
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
    /**
     * The signed envelope the report arrived in, if the host signs.
     *
     * Optional, and its absence is never held against the submission: an unsigned report is
     * an integration that has not adopted signing, not an attack (ADR-0011 §2). A signature
     * that is *present and wrong* is a different matter, and that is the only case that
     * produces evidence.
     */
    val envelope: String? = null,
    /**
     * An upper bound the client asks for on the resulting finding's life.
     *
     * Honoured only where it is shorter than the server's window. ADR-0006 §5: a client may
     * shorten backend freshness and must never be able to extend it.
     */
    val requestedMaxAgeMillis: Long? = null
)

/**
 * What the evidence supports, which is never "this device is fine".
 *
 * There is no `TRUSTED` here and there is no route to one, because this service holds no
 * authenticated anchor: ADR-0008 moved Play Integrity out of scope, and ADR-0007 already
 * established that a report alone cannot exonerate. [NO_EVIDENCE_OF_COMPROMISE] is the
 * strongest thing this service can say, and it is deliberately awkward to read as a pass —
 * a clean device and a client suppressing everything produce it identically.
 *
 * The caller combines this with whatever authenticated signal it holds of its own. That
 * combination is the access decision, and it does not happen here.
 */
enum class DeviceState {
    /** Evidence arrived and it incriminates. The only positive finding this service makes. */
    COMPROMISED,

    /** Nothing in what arrived incriminates. Not a clean bill of health; an absence. */
    NO_EVIDENCE_OF_COMPROMISE,

    /** Nothing usable arrived — no valid challenge, so no finding at all. */
    INSUFFICIENT_EVIDENCE
}

/** Why a finding came out the way it did. Diagnostics, and the reason CI can assert on. */
enum class DecisionReason {
    CHALLENGE_REJECTED,
    SIGNALS_INDICATE_COMPROMISE,
    NO_SIGNAL_INCRIMINATES
}

/**
 * What the server found, and how long it is willing to stand behind it.
 *
 * No action field. This service grades evidence; it does not grant access, and an `ALLOW` it
 * could emit would be an exoneration by another name — see ADR-0008.
 */
data class Decision(
    val deviceState: DeviceState,
    val reason: DecisionReason,
    /** The challenge this finding answers. Null only when redemption never succeeded. */
    val challenge: String?,
    val purpose: ChallengePurpose?,
    val expiresAtMillis: Long
)
