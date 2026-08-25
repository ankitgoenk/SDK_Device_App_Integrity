// Mechanical outcomes of native operations.
//
// ADR-0005. These say what happened, not what it means. "The parser could not parse this"
// is a fact; "this evidence is inconclusive" is a judgement, and judgement belongs to the
// Kotlin scorer, which is the only layer that can see the policy. Nothing resembling
// INCONCLUSIVE appears here on purpose.
//
// Every function returning one is [[nodiscard]]. Without exceptions there is no unwinding
// to make an unhandled failure loud, so an ignored status is a silent bug — the compiler
// is a better reviewer than a reviewer.
#pragma once

namespace integrity {

enum NativeStatus {
    kStatusOk = 0,

    /** A caller-supplied argument was rejected before anything was attempted. */
    kStatusInvalidInput = 10,

    /** The thing being inspected could not be reached at all. */
    kStatusUnavailable = 11,

    /** Input was reached but could not be understood. */
    kStatusParseFailed = 12,

    /** A bug in our code. Ordinary device state must never produce this. */
    kStatusInternalError = 13,
};

}  // namespace integrity

// Values are deliberately disjoint from integrity::SelfCheckStatus in selfcheck.h, which
// carries a different kind of answer (a domain result, not a mechanical outcome) across a
// different JNI method. Keeping the ranges apart means a confusion between the two shows
// up as an obviously wrong number rather than a plausible one. Phase 3b should consider
// consolidating them once the native surface has settled.
