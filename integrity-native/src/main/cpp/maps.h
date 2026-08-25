// Parsing and validation for /proc/self/maps.
//
// No Android headers, no allocation, no STL: this is the half that can be tested on a host
// toolchain in seconds, and the half most likely to be handed malformed input.
#pragma once

#include <cstddef>
#include <cstdint>

#include "status.h"

namespace integrity {

struct MappedRange {
    uintptr_t start;
    uintptr_t end;
    bool readable;
    bool writable;
    bool executable;
};

/**
 * Parses one line of /proc/self/maps.
 *
 * Accepts the address range and permission block; everything after it is ignored, since
 * nothing here needs the path and a path is the part most likely to contain surprises.
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
