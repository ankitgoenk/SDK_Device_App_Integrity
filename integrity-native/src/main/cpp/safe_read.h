// Reading process memory without betting the process on it.
//
// ADR-0005 point 3. Dereferencing an address derived from parsed input risks a SIGSEGV,
// which no amount of C++ exception machinery ever caught. Reading through
// /proc/self/mem turns an unmapped or protected address into an errno instead of a fault.
//
// This is a mitigation, not a guarantee, and it is the assumption ADR-0005 flags for
// on-device confirmation: SELinux policy, kernel version and OEM changes all get a say in
// whether /proc/self/mem is readable. Callers must treat kStatusUnavailable as normal.
#pragma once

#include <stddef.h>
#include <stdint.h>

#include "status.h"

namespace integrity {

/**
 * Reads [address, address + length) of this process into [out].
 *
 * Never dereferences [address]. A bad address produces kStatusUnavailable, and a short
 * read is a failure rather than a silently truncated buffer.
 */
[[nodiscard]] NativeStatus readSelfMemory(uintptr_t address, unsigned char* out, size_t length);

/**
 * As [readSelfMemory], but reading through [path].
 *
 * Exists for testability, and mutation testing is why. Two failure branches — the file not
 * opening, and a read returning zero — cannot be reached through /proc/self/mem on a
 * healthy process, so breaking them changed nothing any test could observe. Code that
 * cannot be reached cannot be tested, and in a security library an untested failure branch
 * is where a wrong answer hides.
 */
[[nodiscard]] NativeStatus readProcessMemory(const char* path, uintptr_t address,
                                             unsigned char* out, size_t length);

/** Largest single read this will attempt. Bounded so a bad length cannot ask for the moon. */
constexpr size_t kMaxSafeReadBytes = 64u * 1024u;

}  // namespace integrity
