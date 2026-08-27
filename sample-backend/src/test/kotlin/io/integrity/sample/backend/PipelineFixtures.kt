package io.integrity.sample.backend

import io.integrity.core.Category
import io.integrity.core.Confidence
import io.integrity.core.Depth
import io.integrity.core.Policy
import io.integrity.core.RiskScorer
import io.integrity.core.Signal
import io.integrity.core.SignalId
import io.integrity.core.Verdict
import io.integrity.core.Weight

/**
 * Deterministic fixtures for the verification pipeline.
 *
 * These establish binding, freshness, replay protection and server-side scoring. They
 * establish nothing about device attestation, which is no longer this project's to perform
 * (ADR-0008) — there is no attestation fixture here to overclaim with any more.
 */

internal val ROOT_SU = SignalId("ROOT_SU_BINARY")
internal val ROOT_MAGISK = SignalId("ROOT_MAGISK_PATHS")
internal val HOOK_FRIDA = SignalId("HOOK_FRIDA_MAPS")
internal val ENV_ADB = SignalId("ENV_ADB_ENABLED")

/**
 * A server policy that actually weights signals.
 *
 * `Policy.balanced()` ships with no weights at all — deliberately, since the SDK promotes a
 * signal only once shadow data justifies it (hard rule 6). One consequence deserves stating
 * plainly: under the default policy no signal can produce COMPROMISED, because `score()`
 * filters to promoted signals before any escalation runs. A backend that took `balanced()`
 * would find nothing incriminating on a rooted device. The scoring policy is the server's to
 * set, and this is what setting it looks like.
 */
internal fun serverPolicy(): Policy = Policy.balanced()
    .withWeight(ROOT_SU, Weight.HIGH)
    .withWeight(ROOT_MAGISK, Weight.HIGH)
    .withWeight(HOOK_FRIDA, Weight.HIGH)
    .withWeight(ENV_ADB, Weight.MEDIUM)

internal fun signal(id: SignalId, confidence: Confidence = Confidence.POSSIBLE, category: Category = Category.META) =
    Signal(id = id, category = category, confidence = confidence, detectedAtMillis = 0L)

/**
 * What a clean device sends: nothing.
 *
 * A detector that finds nothing emits no signal, so this is not an empty edge case — it is the
 * ordinary shape of a healthy report, and the reason the backend can never read a report as
 * exoneration.
 */
internal fun cleanSignals(): List<Signal> = emptyList()

/** Detectors that ran and could not tell. Evidence of nothing, in either direction. */
internal fun inconclusiveSignals(): List<Signal> =
    listOf(ROOT_SU, HOOK_FRIDA).map { signal(it, Confidence.INCONCLUSIVE) }

/** Evidence against interest: a client would not invent these. Scores COMPROMISED. */
internal fun incriminatingSignals(): List<Signal> = listOf(signal(HOOK_FRIDA, Confidence.CONFIRMED, Category.HOOKING))

/**
 * Evidence that reaches SUSPICIOUS but not COMPROMISED: two confirmed root artefacts, no
 * hooking, so no escalation rule fires and the noisy-OR lands at 50 against a 40/75 band.
 *
 * This exists because `tools/mutate-backend.py` proved it had to. Deleting the `SUSPICIOUS`
 * half of the incrimination predicate changed no test result — the branch was live and
 * unexercised, and with attestation gone (ADR-0008) that predicate is the only thing in the
 * pipeline that can produce a finding at all.
 */
internal fun suspiciousSignals(): List<Signal> = listOf(
    signal(ROOT_SU, Confidence.CONFIRMED, Category.ROOT),
    signal(ROOT_MAGISK, Confidence.CONFIRMED, Category.ROOT)
)

/** One rung below: a single confirmed root artefact scores 25, under the 40 bar. */
internal fun lowRiskSignals(): List<Signal> = listOf(signal(ROOT_SU, Confidence.CONFIRMED, Category.ROOT))

internal fun report(
    challenge: String?,
    signals: List<Signal> = cleanSignals(),
    depth: Depth = Depth.STANDARD,
    advisory: ClientAdvisory? = null,
    generatedAtMillis: Long = 0L
) = SubmittedReport(
    challenge = challenge,
    sdkVersion = "0.1.0-alpha01",
    depth = depth,
    signals = signals,
    generatedAtMillis = generatedAtMillis,
    clientAdvisory = advisory
)

internal fun service(
    clock: ServerClock,
    store: ChallengeStore = InMemoryChallengeStore(clock),
    policy: Policy = serverPolicy(),
    decisionPolicy: DecisionPolicy = DecisionPolicy()
) = VerificationService(
    challenges = store,
    scorer = RiskScorer(policy),
    decisionPolicy = decisionPolicy,
    clock = clock
)

/** Convenience: mint a challenge, submit a report answering it, return the finding. */
internal fun VerificationService.submit(
    challenge: Challenge,
    signals: List<Signal> = cleanSignals(),
    advisory: ClientAdvisory? = null,
    requestedMaxAgeMillis: Long? = null,
    sessionId: String = challenge.sessionId,
    purpose: ChallengePurpose = challenge.purpose,
    reportChallenge: String? = challenge.value
): Decision = verify(
    ReportSubmission(
        sessionId = sessionId,
        report = report(reportChallenge, signals, advisory = advisory),
        requestedMaxAgeMillis = requestedMaxAgeMillis
    ),
    purpose
)

internal val ADVISORY_LYING = ClientAdvisory(Verdict.TRUSTED, 0, 1000)
internal val ADVISORY_PANICKING = ClientAdvisory(Verdict.COMPROMISED, 100, 0)
