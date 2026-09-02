package io.integrity.nativecore

import io.integrity.core.Category
import io.integrity.core.Confidence
import io.integrity.core.Depth
import io.integrity.core.DetectionContext
import io.integrity.core.Detector
import io.integrity.core.IntegrityReport
import io.integrity.core.Policy
import io.integrity.core.Signal
import io.integrity.core.SignalId
import io.integrity.core.Weight

/**
 * Reports the state of the SDK's own native core.
 *
 * **Evidence.** `state`, and on a mismatch nothing else — the build token is not reported,
 * since it says more about the build than the decision needs.
 *
 * **Expected result.** Three of the four states are `INCONCLUSIVE` and belong to `META`,
 * because they describe the SDK rather than the device:
 *
 * | State | Signal | Confidence |
 * | --- | --- | --- |
 * | host did not ask for native | `META_NATIVE_NOT_CONFIGURED` | `INCONCLUSIVE` |
 * | expected, would not load | `META_NATIVE_UNAVAILABLE` | `INCONCLUSIVE` |
 * | loaded, call failed | `META_NATIVE_FAILED` | `INCONCLUSIVE` |
 * | loaded, wrong library | `APP_NATIVE_LIB_MISMATCH` | `CONFIRMED`, `APP_TAMPER` |
 *
 * Only the last is a claim about the device, and only because it rests on positive
 * evidence: the library loaded and identified itself as belonging to a different build.
 *
 * **Known bypass.** Deleting the `.so` yields `META_NATIVE_UNAVAILABLE`, which is
 * deliberately weak — a missing ABI, an aggressive repackager and a deliberate deletion
 * are indistinguishable from inside the process, and treating them alike would report the
 * SDK's own fragility as a compromised device. Substituting a library from another build
 * of this SDK is caught; substituting one that reports the right token is not, until the
 * phase-4 digest baseline lands.
 *
 * **False positives.** The dangerous one is `UNAVAILABLE` on devices where loading fails
 * for ordinary reasons: an ABI the host did not package, `extractNativeLibs` interactions,
 * OEM loader behaviour. That is why every state here ships `INFORMATIONAL` and why the
 * weight decision waits for real load-failure rates.
 */
internal class NativeIntegrityDetector(private val core: NativeCore) : Detector {

    override val id: String = "native.core-state"
    override val category: Category = Category.META
    override val minDepth: Depth = Depth.STANDARD

    override suspend fun detect(context: DetectionContext): List<Signal> = when (core.evaluate()) {
        NativeOutcome.OK -> emptyList()
        NativeOutcome.NOT_CONFIGURED -> listOf(
            meta(SignalId.META_NATIVE_NOT_CONFIGURED, "not_configured")
        )
        NativeOutcome.UNAVAILABLE -> listOf(
            meta(SignalId.META_NATIVE_UNAVAILABLE, "load_failed")
        )
        NativeOutcome.FAILED -> listOf(
            meta(SignalId.META_NATIVE_FAILED, "call_failed")
        )
        NativeOutcome.LIBRARY_MISMATCH -> listOf(
            Signal(
                id = SignalId.APP_NATIVE_LIB_MISMATCH,
                category = Category.APP_TAMPER,
                confidence = Confidence.CONFIRMED,
                evidence = mapOf("state" to "library_mismatch")
            )
        )
    }

    private fun meta(id: SignalId, state: String) = Signal(
        id = id,
        category = Category.META,
        confidence = Confidence.INCONCLUSIVE,
        evidence = mapOf("state" to state)
    )
}

/**
 * The native core, phase 3a: it proves it can be delivered and reports its own state.
 * Detection logic — hooking, prologue and GOT checks, memory fingerprints — is phase 3b,
 * deliberately behind this skeleton so that a failure there cannot be confused with a
 * failure to ship native code at all.
 */
public object NativeDetectors {

    /**
     * @param expected whether the host packages the native core. Passing `false` makes a
     *   missing library a configuration fact rather than a finding.
     */
    @JvmStatic
    @JvmOverloads
    public fun all(expected: Boolean = true): List<Detector> = listOf(
        NativeIntegrityDetector(
            NativeCore(expectedByHost = expected, expectedToken = IntegrityReport.SDK_VERSION)
        ),
        SelfTextDetector(expectedByHost = expected)
    )

    /**
     * Intended weight once shadow-mode data supports promotion. Not applied by default: hard
     * rule 6 ships every new signal at `INFORMATIONAL`.
     *
     * This module had no such helper at all, so two of the SDK's nine live detections had no
     * shipped route to a non-zero weight — and `RiskScorer.escalate` only sees signals weighted
     * above `INFORMATIONAL`.
     *
     * **`APP_NATIVE_LIB_MISMATCH` is deliberately absent, and this is the record of that
     * decision.** The catalogue tables it `H`, but its own row says the false-positive mode is
     * "dependency hygiene, not device state": a stale incremental build, an `integrity-native`
     * skewed against a newer `integrity-core`, or an enterprise wrapper rebuilding native libs
     * all produce it with nothing malicious happening. The same row says phase 3b should report
     * the expected and actual tokens, "without them the signal is unactionable". Promoting it
     * before that ships hands an integrator `CONFIRMED` app-tamper evidence they cannot
     * diagnose. Add it here in the PR that makes it diagnosable, not before.
     *
     * `HOOK_SELF_TEXT_MISMATCH` moves the score and not the escalation, by design: the detector
     * caps itself at `POSSIBLE` "and never higher, on any device", and the hooking escalation
     * rule fires only on `CONFIRMED`. `HIGH` x 0.4 is 10 points into `HOOKING`. Raising the
     * confidence to make that rule fire would be inverting the detector's own conclusion.
     */
    @JvmStatic
    public fun proposedWeights(policy: Policy): Policy = policy
        .withWeight(SignalId.HOOK_SELF_TEXT_MISMATCH, Weight.HIGH)
}
