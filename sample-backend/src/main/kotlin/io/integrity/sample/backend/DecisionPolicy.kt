package io.integrity.sample.backend

/**
 * How long a finding is good for.
 *
 * Backend-authoritative and configurable, per ADR-0006: these numbers are the server's to
 * change without an app release.
 *
 * There is no device-state-to-action table here any more. This service grades evidence and
 * the caller decides access (ADR-0008), so the only policy left on this side is freshness.
 * The mapping that used to live here — `TRUSTED to ALLOW` and the rest — belongs wherever the
 * authenticated anchor now lives, because that is the only place both halves are in hand.
 */
class DecisionPolicy(
    private val ordinaryWindowMillis: Long = ORDINARY_WINDOW_MILLIS,
    private val sensitiveWindowMillis: Long = SENSITIVE_WINDOW_MILLIS
) {

    fun windowFor(purpose: ChallengePurpose): Long =
        if (purpose == ChallengePurpose.SENSITIVE_ACTION) sensitiveWindowMillis else ordinaryWindowMillis

    companion object {
        /** ADR-0006, Resolved 2: 30 minutes for ordinary use, initially. */
        const val ORDINARY_WINDOW_MILLIS: Long = 30 * 60 * 1000L

        /**
         * A sensitive finding answers one action. Short by design: the point is that the
         * action derives its own challenge rather than riding an existing window.
         */
        const val SENSITIVE_WINDOW_MILLIS: Long = 2 * 60 * 1000L
    }
}
