// On a 32-bit ABI — armeabi-v7a, which this SDK ships — off_t defaults to a 32-bit
// *signed* type. Addresses are unsigned, so any address at or above 0x80000000 would cast
// to a negative offset, pread would fail with EINVAL, and readSelfMemory would report
// kStatusUnavailable for a perfectly valid address. Not a crash: a silent wrong answer for
// the upper half of the address space, which would make a phase 3b detector quietly blind
// on 32-bit devices.
//
// _FILE_OFFSET_BITS=64 makes off_t 64-bit and routes pread to pread64. Supported on
// Android from API 24, which is this SDK's minSdk. Must precede every include.
#define _FILE_OFFSET_BITS 64

#include "safe_read.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>

// The define above is load-bearing and silent if it stops working, so assert it.
static_assert(sizeof(off_t) == 8, "off_t must be 64-bit; see _FILE_OFFSET_BITS above");

namespace integrity {
namespace {

constexpr const char* kSelfMem = "/proc/self/mem";

}  // namespace

NativeStatus readSelfMemory(uintptr_t address, unsigned char* out, size_t length) {
    if (out == nullptr || length == 0 || length > kMaxSafeReadBytes) {
        return kStatusInvalidInput;
    }
    if (address > UINTPTR_MAX - length) {
        return kStatusInvalidInput;
    }

    const int fd = open(kSelfMem, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return kStatusUnavailable;
    }

    NativeStatus status = kStatusOk;
    size_t done = 0;
    while (done < length) {
        const ssize_t got = pread(fd, out + done, length - done,
                                  static_cast<off_t>(address + done));
        if (got < 0) {
            // EIO is what an unmapped offset produces, and is the case this exists for.
            status = (errno == EINTR) ? kStatusOk : kStatusUnavailable;
            if (status == kStatusUnavailable) {
                break;
            }
            continue;
        }
        if (got == 0) {
            status = kStatusUnavailable;
            break;
        }
        done += static_cast<size_t>(got);
    }

    close(fd);
    return status;
}

}  // namespace integrity
