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
 *
 * **No member of this enum means "trusted", and that is deliberate (ADR-0009).** The bottom
 * rung used to be called `TRUSTED`, which made `if (report.verdict == TRUSTED) allow()` the
 * obvious thing to write — a decision taken on the device, from unsigned local evidence,
 * which is the single failure this architecture exists to prevent. ADR-0006 §2 had already
 * moved `verdict` under `clientAdvisory` on the wire for exactly that reason; the in-process
 * type kept the hazard until ADR-0009 removed the name.
 */
public enum class Verdict {
    /**
     * Scored below the low-risk floor: nothing found that carries weight.
     *
     * An absence, not a pass. A healthy device and a client patched to stay silent produce
     * this identically, so it can never be a reason to permit anything.
     */
    NO_EVIDENCE_OF_COMPROMISE,
    LOW_RISK,
    SUSPICIOUS,
    COMPROMISED,

    /** Not initialised, or coverage too low for the result to mean anything. */
    UNKNOWN
}
