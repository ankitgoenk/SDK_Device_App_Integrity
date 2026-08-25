#define _FILE_OFFSET_BITS 64

#include "selftext.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "maps.h"
#include "safe_read.h"

static_assert(sizeof(off_t) == 8, "off_t must be 64-bit; see safe_read.cpp");

namespace integrity {
namespace {

constexpr size_t kLineBytes = 512;
constexpr size_t kPathBytes = 256;
// One read at a time, well inside kMaxSafeReadBytes. Fixed, because there is no allocator
// here and a bad length must not be able to ask for the moon (ADR-0005 point 4).
constexpr size_t kChunkBytes = 4096;

/** Copies a path window out of a maps line. Refuses rather than truncating. */
bool copyPath(const char* line, size_t offset, size_t length, char* out, size_t capacity) {
    if (length == 0 || length + 1 > capacity) {
        return false;
    }
    memcpy(out, line + offset, length);
    out[length] = '\0';
    return true;
}

}  // namespace

NativeStatus measureSelfTextFrom(const char* mapsPath, SelfTextMeasurement* out) {
    if (mapsPath == nullptr || out == nullptr) {
        return kStatusInvalidInput;
    }
    out->mappingsFound = 0;
    out->bytesCompared = 0;
    out->bytesDiffering = 0;
    out->firstDifferenceAt = 0;

    // The mapping containing this function belongs, by definition, to whatever module this
    // code was linked into. No name matching and no assumption about where the library
    // lives, and it behaves identically in a host binary and in an .so.
    const uintptr_t inside = reinterpret_cast<uintptr_t>(&measureSelfTextFrom);

    FILE* maps = fopen(mapsPath, "r");
    if (maps == nullptr) {
        return kStatusUnavailable;
    }

    char line[kLineBytes];
    char ours[kPathBytes];
    bool identified = false;

    // First pass: which file are we? Second pass: every executable mapping from that file.
    //
    // One pass over the mapping that happens to contain this function is not enough, and
    // the fixture proved it: mprotect splits a VMA, so patching a page can move it into a
    // mapping of its own. A module with several executable segments has the same shape
    // without anyone patching anything, and half an inspection reported as a clean result
    // is exactly the silence this measurement exists to avoid.
    while (fgets(line, sizeof(line), maps) != nullptr) {
        MappedRange candidate{};
        if (parseMapsLine(line, strlen(line), &candidate) != kStatusOk) {
            continue;
        }
        if (!candidate.executable || inside < candidate.start || inside >= candidate.end) {
            continue;
        }
        if (copyPath(line, candidate.pathOffset, candidate.pathLength, ours, sizeof(ours))) {
            identified = true;
        }
        break;
    }

    if (!identified) {
        fclose(maps);
        return kStatusUnavailable;
    }

    rewind(maps);
    NativeStatus status = kStatusOk;
    char path[kPathBytes];
    unsigned char fromMemory[kChunkBytes];
    unsigned char fromFile[kChunkBytes];

    while (fgets(line, sizeof(line), maps) != nullptr) {
        MappedRange range{};
        if (parseMapsLine(line, strlen(line), &range) != kStatusOk) {
            continue;
        }
        if (!range.executable || !range.readable) {
            continue;
        }
        if (!copyPath(line, range.pathOffset, range.pathLength, path, sizeof(path))) {
            continue;
        }
        if (strcmp(path, ours) != 0) {
            continue;
        }

        const int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            status = kStatusUnavailable;
            break;
        }
        ++out->mappingsFound;

        for (uintptr_t address = range.start; address < range.end;) {
            const uintptr_t remaining = range.end - address;
            const size_t want =
                remaining < kChunkBytes ? static_cast<size_t>(remaining) : kChunkBytes;

            if (readSelfMemory(address, fromMemory, want) != kStatusOk) {
                status = kStatusUnavailable;
                break;
            }

            const off_t at = static_cast<off_t>(range.fileOffset + (address - range.start));
            const ssize_t got = pread(fd, fromFile, want, at);
            if (got < 0) {
                status = kStatusUnavailable;
                break;
            }
            if (got == 0) {
                // The mapping runs past the end of the file. Legitimate: the tail is
                // zero-fill rather than code from disk, so stop instead of calling padding
                // a mismatch.
                break;
            }

            const size_t comparable = static_cast<size_t>(got);
            for (size_t i = 0; i < comparable; ++i) {
                if (fromMemory[i] != fromFile[i]) {
                    if (out->bytesDiffering == 0) {
                        out->firstDifferenceAt = (address - range.start) + i;
                    }
                    ++out->bytesDiffering;
                }
            }
            out->bytesCompared += comparable;
            address += comparable;
        }

        close(fd);
        if (status != kStatusOk) {
            break;
        }
    }
    fclose(maps);

    if (status != kStatusOk) {
        return status;
    }
    // Having compared nothing is not a clean result. Reporting kStatusOk here would let
    // "no differences" mean "no inspection", which is the whole failure this measurement
    // was written to rule out.
    if (out->mappingsFound == 0 || out->bytesCompared == 0) {
        return kStatusUnavailable;
    }
    return kStatusOk;
}

NativeStatus measureSelfText(SelfTextMeasurement* out) {
    return measureSelfTextFrom("/proc/self/maps", out);
}

}  // namespace integrity
