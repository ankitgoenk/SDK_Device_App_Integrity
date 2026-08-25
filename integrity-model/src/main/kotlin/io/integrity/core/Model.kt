package io.integrity.core

/** Broad family a [Signal] belongs to. Used for per-category scoring and caps. */
public enum class Category {
    ROOT,
    HOOKING,
    APP_TAMPER,
    ENVIRONMENT,
    EMULATION,
    ATTESTATION,
    META
}

/**
 * How much the detector believes its own observation.
 *
 * [INCONCLUSIVE] is a first-class result: it means the check could not run, which is
 * different from the check running and finding nothing. It contributes to coverage,
 * never to the risk score.
 */
public enum class Confidence {
    CONFIRMED,
    LIKELY,
    POSSIBLE,
    INCONCLUSIVE
}

/** How much work an evaluation is allowed to do. See docs/API_DESIGN.md. */
public enum class Depth {
    /** Cached results and O(1) checks only. Target <= 20 ms. */
    QUICK,

    /** Adds filesystem probes, package queries, JVM hook probes. Target <= 150 ms. */
    STANDARD,

    /** Adds native scans, socket probes, digest verification, attestation. Target <= 1 s. */
    FULL
}

/**
 * The SDK's summary opinion. Hosts should treat this as risk input, not as truth:
 * a patched client can report anything. See docs/SERVER_VERIFICATION.md.
 */
public enum class Verdict {
    TRUSTED,
    LOW_RISK,
    SUSPICIOUS,
    COMPROMISED,

    /** Not initialised, or coverage too low for the result to mean anything. */
    UNKNOWN
}
