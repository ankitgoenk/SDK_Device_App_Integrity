package io.integrity.sample.backend

/**
 * How the server turns a device state into an action, and how long the answer is good for.
 *
 * Backend-authoritative and configurable, per ADR-0006: these numbers are the server's to
 * change without an app release.
 */
class DecisionPolicy(
    private val ordinaryActions: Map<DeviceState, Action> = DEFAULT_ORDINARY,
    private val sensitiveActions: Map<DeviceState, Action> = DEFAULT_SENSITIVE,
    private val ordinaryWindowMillis: Long = ORDINARY_WINDOW_MILLIS,
    private val sensitiveWindowMillis: Long = SENSITIVE_WINDOW_MILLIS
) {

    fun actionFor(state: DeviceState, purpose: ChallengePurpose): Action {
        val table =
            if (purpose == ChallengePurpose.SENSITIVE_ACTION) sensitiveActions else ordinaryActions
        // An unmapped state is not an excuse to allow. DENY is the only safe default for a
        // lookup miss in a table that decides access.
        return table[state] ?: Action.DENY
    }

    fun windowFor(purpose: ChallengePurpose): Long =
        if (purpose == ChallengePurpose.SENSITIVE_ACTION) sensitiveWindowMillis else ordinaryWindowMillis

    companion object {
        /** ADR-0006, Resolved 2: 30 minutes for ordinary use, initially. */
        const val ORDINARY_WINDOW_MILLIS: Long = 30 * 60 * 1000L

        /**
         * A sensitive decision answers one action. Short by design: the point is that the
         * action derives its own challenge rather than riding an existing window.
         */
        const val SENSITIVE_WINDOW_MILLIS: Long = 2 * 60 * 1000L

        val DEFAULT_ORDINARY: Map<DeviceState, Action> = mapOf(
            DeviceState.TRUSTED to Action.ALLOW,
            DeviceState.COMPROMISED to Action.DENY,
            DeviceState.UNAVAILABLE to Action.STEP_UP,
            DeviceState.INSUFFICIENT_EVIDENCE to Action.STEP_UP
        )

        /** Strictly no weaker than ordinary, for every state. A test asserts that. */
        val DEFAULT_SENSITIVE: Map<DeviceState, Action> = mapOf(
            DeviceState.TRUSTED to Action.ALLOW,
            DeviceState.COMPROMISED to Action.DENY,
            DeviceState.UNAVAILABLE to Action.DENY,
            DeviceState.INSUFFICIENT_EVIDENCE to Action.REVIEW
        )
    }
}
