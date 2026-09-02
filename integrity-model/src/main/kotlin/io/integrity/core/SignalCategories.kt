package io.integrity.core

/**
 * The [Category] a [SignalId] belongs to, derived from the id rather than taken on trust.
 *
 * ### Why this exists
 *
 * A signal's category is a fact about its id — `HOOK_UNEXPECTED_MODULE` is always `HOOKING`, and
 * `docs/DETECTION_CATALOG.md` is organised by exactly this. It is not something a device gets an
 * opinion about. But it arrived on the wire, and `RiskScorer` keys an escalation rule on it:
 *
 * ```
 * val confirmedHooking = signals.any { it.category == Category.HOOKING && it.confidence == CONFIRMED }
 * if (confirmedHooking) verdict = verdict.atLeast(Verdict.COMPROMISED)
 * ```
 *
 * So an attacker-controlled string steered a rule that forces `COMPROMISED`. One altered
 * character — `HOOKING` to `HOOKlNG` — failed to parse, fell back to `Category.META`, and the
 * rule stopped seeing it. The backend's own comment argued against precisely that outcome:
 * "Dropping incriminating evidence because one of its labels was unfamiliar would let a client
 * shed a signal by misspelling its category."
 *
 * Deriving removes the input instead of validating it, which is the stronger move and leaves no
 * comparison for a later refactor to drop.
 *
 * ### Why prefixes, and not a table of constants
 *
 * `SignalId` has 18 constants; the catalogue has 84 rows. A table of constants would leave the
 * other 66 — and any `ATT_*` id an integrator supplies for their own attestation verdicts, which
 * `DETECTION_TRIAGE.md` §8 says is a supported thing to do — falling back to the client's word.
 * The prefix *is* the family, in the catalogue and in every detector that ships.
 *
 * Returns null for an id in no known family, which is a real case: an integrator's own id. Such
 * a signal keeps whatever category it arrived with, and carries `INFORMATIONAL` weight anyway
 * until someone deliberately weights it.
 */
public object SignalCategories {

    private val BY_PREFIX = mapOf(
        "ROOT" to Category.ROOT,
        "HOOK" to Category.HOOKING,
        "APP" to Category.APP_TAMPER,
        "ENV" to Category.ENVIRONMENT,
        "EMU" to Category.EMULATION,
        // Virtual containers are catalogued beside emulators and scored with them.
        "VIRT" to Category.EMULATION,
        "ATT" to Category.ATTESTATION,
        "META" to Category.META,
        // Findings the backend makes about a submission rather than about a device. It grades
        // them with app tampering because that is what a report which does not match its
        // claimed origin is evidence of -- and it is where `SRV_REPORT_SIGNATURE_INVALID`
        // already sat before this object existed.
        "SRV" to Category.APP_TAMPER
    )

    /** The category [id] belongs to, or null if its family is not one this build knows. */
    public fun of(id: SignalId): Category? = BY_PREFIX[id.value.substringBefore('_')]
}
