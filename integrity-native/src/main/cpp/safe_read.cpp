#include "safe_read.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

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
