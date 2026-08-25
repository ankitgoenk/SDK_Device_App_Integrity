// Parsing and validation for /proc/self/maps.
//
// No Android headers, no allocation, no STL: this is the half that can be tested on a host
// toolchain in seconds, and the half most likely to be handed malformed input.
#pragma once

#include <stddef.h>
#include <stdint.h>

#include "status.h"

namespace integrity {

struct MappedRange {
    uintptr_t start;
    uintptr_t end;
    bool readable;
    bool writable;
    bool executable;

    /** Offset into the backing file at which this mapping begins. Zero when anonymous. */
    uintptr_t fileOffset;

    // The path is returned as a window into the caller's line rather than copied. There is
    // no allocator here (ADR-0005 point 4), and a fixed buffer would either truncate real
    // paths or bloat every range. The caller owns the line and must keep it alive.
    size_t pathOffset;
    size_t pathLength;  // zero for an anonymous mapping
};

/**
 * Parses one line of /proc/self/maps.
 *
 * Reads the address range, the permission block, the file offset and the path. The offset
 * and path used to be ignored on the grounds that nothing needed them; comparing a mapping
 * against the file it came from needs both, and the path is still the part most likely to
 * contain surprises, so it is returned as bounds into the caller's buffer and never copied
 * or interpreted here.
 *
 * The whole line must be well formed. A line truncated after the permission block is a
 * parse failure, not a partial success: half a maps line is not evidence about a mapping.
 */
[[nodiscard]] NativeStatus parseMapsLine(const char* line, size_t length, MappedRange* out);

/**
 * Whether [address, address + length) is safe to read within [range].
 *
 * A parser can be perfectly correct and still hand back a range that is not safe to touch,
 * so this is a separate question from whether the line parsed. Overflow is checked before
 * anything else: address + length wrapping is exactly how a plausible-looking range turns
 * into an uncontrolled access.
 */
[[nodiscard]] NativeStatus rangeIsReadable(const MappedRange& range, uintptr_t address, size_t length);

}  // namespace integrity
