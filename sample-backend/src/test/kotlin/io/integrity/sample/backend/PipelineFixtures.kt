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
 * **These verify nothing about Google.** Every attestation outcome below is fabricated. They
 * establish binding, freshness, replay protection, requestHash/challenge relationships and
 * server-side scoring; they establish precisely nothing about whether a real Play Integrity
 * token is genuine, because no code here parses or checks a real one. Anything claiming
 * otherwise would be the overclaim this project keeps catching itself in.
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
 * and relied on signal scoring would trust a rooted device. The scoring policy is the
 * server's to set, and this is what setting it looks like.
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

/** Evidence against interest: a client would not invent these. */
internal fun incriminatingSignals(): List<Signal> = listOf(signal(HOOK_FRIDA, Confidence.CONFIRMED, Category.HOOKING))

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

/** A verifier that answers exactly what a test tells it to. Never talks to Google. */
internal class ScriptedVerifier(private val outcome: (String) -> AttestationOutcome) :
    PlayIntegrityVerifier,
    NotForProduction {
    override fun verify(token: String): AttestationOutcome = outcome(token)
}

/** The happy-path verifier: token is the challenge, echoed back as a matching requestHash. */
internal fun verifierEchoing(challengeOf: (String) -> String = { it }) = ScriptedVerifier { token ->
    AttestationOutcome.Verified(
        appRecognised = true,
        deviceRecognised = true,
        requestHash = RequestHash.of(challengeOf(token))
    )
}

internal fun service(
    clock: ServerClock,
    verifier: PlayIntegrityVerifier = verifierEchoing(),
    store: ChallengeStore = InMemoryChallengeStore(clock),
    policy: Policy = serverPolicy(),
    decisionPolicy: DecisionPolicy = DecisionPolicy()
) = VerificationService(
    challenges = store,
    verifier = verifier,
    scorer = RiskScorer(policy),
    decisionPolicy = decisionPolicy,
    clock = clock
)

/** Convenience: mint a challenge, submit a report answering it, return the decision. */
internal fun VerificationService.submit(
    challenge: Challenge,
    signals: List<Signal> = cleanSignals(),
    advisory: ClientAdvisory? = null,
    token: String? = challenge.value,
    requestedMaxAgeMillis: Long? = null,
    sessionId: String = challenge.sessionId,
    purpose: ChallengePurpose = challenge.purpose
): Decision = verify(
    ReportSubmission(
        sessionId = sessionId,
        report = report(challenge.value, signals, advisory = advisory),
        playIntegrityToken = token,
        requestedMaxAgeMillis = requestedMaxAgeMillis
    ),
    purpose
)

internal val ADVISORY_LYING = ClientAdvisory(Verdict.TRUSTED, 0, 1000)
internal val ADVISORY_PANICKING = ClientAdvisory(Verdict.COMPROMISED, 100, 0)
