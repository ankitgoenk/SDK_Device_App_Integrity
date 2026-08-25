// Comparing this library's executing code against the file it was loaded from.
//
// PR #12 of the plan in docs/detectors/HOOK_SELF_TEXT_MISMATCH.md: this is the measurement
// that decides whether the detector is worth building. It reports what it found and makes
// no judgement — there is no Signal, no Confidence and no policy here, because the question
// being answered is whether a clean process really does have memory matching disk.
//
// Deliberately free of Android headers, so the same code that will run on a device runs
// under the host suite, the sanitizer and the mutation gate.
#pragma once

#include <stddef.h>
#include <stdint.h>

#include "status.h"

namespace integrity {

struct SelfTextMeasurement {
    /** Executable mappings belonging to this module that were located and opened. */
    uint32_t mappingsFound;
    /** Bytes actually compared. Zero means nothing was checked, never "nothing was wrong". */
    uint64_t bytesCompared;
    /** Bytes that differ between memory and the file. */
    uint64_t bytesDiffering;
    /** Offset within the mapping of the first difference; only meaningful when differing. */
    uint64_t firstDifferenceAt;
};

/**
 * Compares the executable mapping containing this function against its backing file.
 *
 * Reports `kStatusOk` when a comparison completed, whatever the outcome of that comparison:
 * finding differences is a result, not an error. `kStatusUnavailable` means the comparison
 * could not be made — no mapping found, `/proc` unreadable, the file unopenable — and the
 * caller must treat that as "not checked" rather than "clean".
 */
[[nodiscard]] NativeStatus measureSelfText(SelfTextMeasurement* out);

/** As [measureSelfText], but reading the mapping table from [mapsPath]. For tests. */
[[nodiscard]] NativeStatus measureSelfTextFrom(const char* mapsPath, SelfTextMeasurement* out);

}  // namespace integrity
