// Host-runnable tests for the parsing, validation and safe-read logic.
//
// The property under test is not "the parser rejects garbage". It is stronger:
// **malformed or unsafe input cannot turn into an uncontrolled native memory access.**
// A parser can be perfectly correct and still hand back a range that is not safe to touch,
// so the range checks and the safe read are tested separately from the parsing.
#include <cstdio>
#include <cstring>
#include <string>

#include "../maps.h"
#include "../safe_read.h"
#include "../selfcheck.h"

namespace {

int failures = 0;

void expect(bool condition, const char* what) {
    if (!condition) {
        std::printf("FAIL: %s\n", what);
        ++failures;
    }
}

integrity::NativeStatus parse(const std::string& line, integrity::MappedRange* out) {
    return integrity::parseMapsLine(line.c_str(), line.size(), out);
}

void buildTokenTests() {
    expect(integrity::verifyBuildToken(integrity::buildToken()) == integrity::kOk,
           "the compiled-in token verifies against itself");
    expect(integrity::verifyBuildToken("not-the-token") == integrity::kTokenMismatch,
           "a different token is a mismatch");
    expect(integrity::verifyBuildToken(nullptr) == integrity::kBadArgument,
           "a null token is rejected rather than dereferenced");

    const char* token = integrity::buildToken();
    const size_t length = std::strlen(token);
    if (length > 1) {
        const std::string prefix(token, length - 1);
        expect(integrity::verifyBuildToken(prefix.c_str()) == integrity::kTokenMismatch,
               "a prefix of the real token is a mismatch");
        expect(integrity::verifyBuildToken((std::string(token) + "x").c_str()) ==
                   integrity::kTokenMismatch,
               "the real token with a suffix is a mismatch");
    } else {
        std::printf("FAIL: build token too short to test meaningfully\n");
        ++failures;
    }
}

// Case 1: a valid mapping parses.
void validMappingTests() {
    integrity::MappedRange range{};
    expect(parse("7f8a2c000000-7f8a2c021000 r-xp 00000000 fd:00 1234  /system/lib64/libc.so",
                 &range) == integrity::kStatusOk,
           "a real maps line parses");
    expect(range.start == 0x7f8a2c000000ull && range.end == 0x7f8a2c021000ull,
           "the address range is read correctly");
    expect(range.readable && range.executable && !range.writable,
           "permissions are read correctly");

    integrity::MappedRange anonymous{};
    expect(parse("aaaa-bbbb rw-p 00000000 00:00 0", &anonymous) == integrity::kStatusOk,
           "an anonymous mapping with no path parses");
    expect(anonymous.writable && !anonymous.executable, "rw- is not executable");
}

// Case 2: malformed input is rejected, never accepted-with-garbage.
void malformedMappingTests() {
    integrity::MappedRange range{};

    expect(integrity::parseMapsLine(nullptr, 10, &range) == integrity::kStatusInvalidInput,
           "a null line is invalid input");
    expect(integrity::parseMapsLine("aaaa-bbbb r--p", 14, nullptr) == integrity::kStatusInvalidInput,
           "a null output is invalid input");
    expect(parse("", &range) == integrity::kStatusInvalidInput, "an empty line is invalid input");

    const char* garbage[] = {
        "not a maps line at all",
        "zzzz-bbbb r--p 0",              // non-hex start
        "aaaa bbbb r--p 0",              // missing separator
        "aaaa-  r--p 0",                 // missing end address
        "aaaa-bbbb",                     // truncated before permissions
        "aaaa-bbbb r-",                  // truncated inside permissions
        "aaaa-bbbb qrst 0",              // nonsense permissions
        "bbbb-aaaa r--p 0",              // end before start
        "-bbbb r--p 0",                  // missing start
    };
    for (const char* line : garbage) {
        char message[160];
        std::snprintf(message, sizeof(message), "malformed line rejected: %s", line);
        expect(parse(line, &range) == integrity::kStatusParseFailed, message);
    }

    // An address so long it would wrap must be refused, not truncated into something
    // plausible — a wrapped value is exactly how a bad line becomes a valid-looking range.
    const std::string overflowing = std::string(40, 'f') + "-bbbb r--p 0";
    expect(parse(overflowing, &range) == integrity::kStatusParseFailed,
           "an address that would overflow is rejected");
}

// Case 3: input that parses cleanly but is not safe to access.
void unsafeRangeTests() {
    const integrity::MappedRange readable{0x1000, 0x2000, true, false, false};
    const integrity::MappedRange unreadable{0x1000, 0x2000, false, false, false};

    expect(integrity::rangeIsReadable(readable, 0x1000, 0x1000) == integrity::kStatusOk,
           "the whole mapping is readable");
    expect(integrity::rangeIsReadable(readable, 0x1fff, 1) == integrity::kStatusOk,
           "the last byte is readable");

    expect(integrity::rangeIsReadable(readable, 0x1000, 0) == integrity::kStatusInvalidInput,
           "a zero-length read is invalid input");
    expect(integrity::rangeIsReadable(readable, UINTPTR_MAX - 4, 16) == integrity::kStatusInvalidInput,
           "a read whose end wraps is invalid input");
    expect(integrity::rangeIsReadable(readable, 0x0fff, 2) == integrity::kStatusUnavailable,
           "a read starting before the mapping is unavailable");
    expect(integrity::rangeIsReadable(readable, 0x1fff, 2) == integrity::kStatusUnavailable,
           "a read running past the end is unavailable");
    expect(integrity::rangeIsReadable(unreadable, 0x1000, 4) == integrity::kStatusUnavailable,
           "a non-readable mapping is unavailable");
}

// The property that matters: a bad address returns a status instead of killing us.
void safeReadTests() {
    unsigned char buffer[64];

    const uintptr_t own = reinterpret_cast<uintptr_t>(&safeReadTests);
    const integrity::NativeStatus ok = integrity::readSelfMemory(own, buffer, sizeof(buffer));
    expect(ok == integrity::kStatusOk || ok == integrity::kStatusUnavailable,
           "reading our own text either works or reports unavailable, never crashes");

    expect(integrity::readSelfMemory(0, buffer, sizeof(buffer)) == integrity::kStatusUnavailable,
           "reading the null page reports unavailable rather than faulting");
    expect(integrity::readSelfMemory(0xdead0000ull, buffer, sizeof(buffer)) ==
               integrity::kStatusUnavailable,
           "reading an unmapped address reports unavailable rather than faulting");

    expect(integrity::readSelfMemory(own, nullptr, 16) == integrity::kStatusInvalidInput,
           "a null destination is invalid input");
    expect(integrity::readSelfMemory(own, buffer, 0) == integrity::kStatusInvalidInput,
           "a zero length is invalid input");
    expect(integrity::readSelfMemory(own, buffer, integrity::kMaxSafeReadBytes + 1) ==
               integrity::kStatusInvalidInput,
           "an oversized length is refused rather than attempted");
}

}  // namespace

int main() {
    buildTokenTests();
    validMappingTests();
    malformedMappingTests();
    unsafeRangeTests();
    safeReadTests();

    if (failures == 0) {
        std::printf("OK: native host tests passed\n");
    }
    return failures == 0 ? 0 : 1;
}
