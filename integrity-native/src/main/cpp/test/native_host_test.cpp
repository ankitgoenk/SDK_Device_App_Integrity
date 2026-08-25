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

// Address fixtures have to be width-dependent, and that is the point rather than an
// inconvenience: a 32-bit process never sees a 48-bit address in its own maps, and its
// uintptr_t could not hold one. Weakening the assertion to something both widths satisfy
// would test neither. Each width gets the address range it actually has.
#if UINTPTR_MAX > 0xffffffffu
const char* const kMappingLine =
    "7f8a2c000000-7f8a2c021000 r-xp 00000000 fd:00 1234  /system/lib64/libc.so";
const uintptr_t kMappingStart = 0x7f8a2c000000ull;
const uintptr_t kMappingEnd = 0x7f8a2c021000ull;
#else
// Deliberately above 0x80000000: this is where armeabi-v7a actually maps libc, and it is
// the half of the address space the off_t bug silently lost.
const char* const kMappingLine =
    "b6f2c000-b6f4d000 r-xp 00000000 fd:00 1234  /system/lib/libc.so";
const uintptr_t kMappingStart = 0xb6f2c000u;
const uintptr_t kMappingEnd = 0xb6f4d000u;
#endif

integrity::NativeStatus parse(const std::string& line, integrity::MappedRange* out) {
    return integrity::parseMapsLine(line.c_str(), line.size(), out);
}

/**
 * Finds an address this process really has no mapping for.
 *
 * A fixed constant used to stand in for "unmapped", and that was an assertion about the
 * address space rather than about the code. Under AddressSanitizer 0xdead0000 falls inside
 * a shadow mapping and reads back perfectly, so the test failed against correct code —
 * which is how this was found. Establish the fixture, or the conclusion is about the build
 * configuration.
 *
 * Returns false when /proc/self/maps cannot be consulted; the caller must then say so
 * rather than quietly asserting nothing.
 */
bool findUnmappedAddress(uintptr_t* out) {
    const uintptr_t candidates[] = {
        0xdead0000u, 0x00010000u, 0x20000000u, 0x60000000u,
        static_cast<uintptr_t>(0x0000700000000000ull & UINTPTR_MAX),
    };

    std::FILE* maps = std::fopen("/proc/self/maps", "r");
    if (maps == nullptr) return false;

    bool taken[sizeof(candidates) / sizeof(candidates[0])] = {false};
    char line[512];
    while (std::fgets(line, sizeof(line), maps) != nullptr) {
        integrity::MappedRange range{};
        if (integrity::parseMapsLine(line, std::strlen(line), &range) != integrity::kStatusOk) {
            continue;
        }
        for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); ++i) {
            if (candidates[i] >= range.start && candidates[i] < range.end) taken[i] = true;
        }
    }
    std::fclose(maps);

    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); ++i) {
        if (!taken[i] && candidates[i] != 0) {
            *out = candidates[i];
            return true;
        }
    }
    return false;
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
    expect(parse(kMappingLine, &range) == integrity::kStatusOk, "a real maps line parses");
    expect(range.start == kMappingStart && range.end == kMappingEnd,
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

    // The contract is (pointer, length), not "a C string". Every case above happens to pass
    // NUL-terminated data, which let a read one past the end look harmless: the byte there
    // was always '\0'. This buffer has no terminator, so an off-by-one reads real memory.
    {
        const char unterminated[] = {'a', 'a', 'a', 'a'};  // start address, then nothing
        integrity::MappedRange range2{};
        expect(integrity::parseMapsLine(unterminated, sizeof(unterminated), &range2) ==
                   integrity::kStatusParseFailed,
               "a buffer that ends after the start address is rejected without reading past it");
    }

    // An address so long it would wrap must be refused, not truncated into something
    // plausible — a wrapped value is exactly how a bad line becomes a valid-looking range.
    const std::string overflowing = std::string(40, 'f') + "-bbbb r--p 0";
    expect(parse(overflowing, &range) == integrity::kStatusParseFailed,
           "an address that would overflow is rejected");

#if UINTPTR_MAX <= 0xffffffffu
    // The realistic version of the same wrap. A 64-bit maps line is not garbage — it is
    // exactly what a 64-bit process emits — but it cannot fit a 32-bit uintptr_t. Truncating
    // 0x7f8a2c000000 yields 0x2c000000: a plausible address in a completely different
    // mapping, which is far more dangerous than an obviously bad one. It must be refused.
    integrity::MappedRange tooWide{};
    expect(parse("7f8a2c000000-7f8a2c021000 r-xp 00000000 fd:00 1234  /system/lib64/libc.so",
                 &tooWide) == integrity::kStatusParseFailed,
           "a 64-bit address is refused on a 32-bit build, never truncated");
#endif
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

    // The off_t regression this build width exists to catch, asserted directly. Nothing else
    // here catches it: an address above the sign boundary casts to a negative file offset,
    // pread fails with EINVAL, and readSelfMemory reports kStatusUnavailable — which is also
    // the correct answer for an unmapped address, so every existing assertion stays green
    // while half the address space silently stops being readable.
    //
    // Stated as a relative property so it cannot be flaky: /proc/self/mem may be restricted
    // in some environments, and then neither read succeeds and there is nothing to compare.
    // But if a low address can be read at all, a high one must be readable too.
    unsigned char onTheStack = 0;
    const uintptr_t stack = reinterpret_cast<uintptr_t>(&onTheStack);
    const uintptr_t lower = stack < own ? stack : own;
    const uintptr_t higher = stack < own ? own : stack;

    if (integrity::readSelfMemory(lower, buffer, sizeof(buffer)) == integrity::kStatusOk) {
        expect(integrity::readSelfMemory(higher, buffer, sizeof(buffer)) == integrity::kStatusOk,
               "a high address reads as well as a low one (off_t must not truncate)");
    } else {
        // Skipping is legitimate, staying quiet about it is not: a green log would otherwise
        // be indistinguishable from one where this property was actually exercised.
        std::printf("SKIPPED: /proc/self/mem unreadable here, off_t property not exercised\n");
    }

#if UINTPTR_MAX <= 0xffffffffu
    // And the check above must not quietly become vacuous: on 32 bits the stack sits near
    // 0xff000000, so if no address here crosses the boundary, the test is not testing it.
    expect(higher > (UINTPTR_MAX / 2),
           "the 32-bit run must exercise an address above the off_t sign boundary");
#endif

    expect(integrity::readSelfMemory(0, buffer, sizeof(buffer)) == integrity::kStatusUnavailable,
           "reading the null page reports unavailable rather than faulting");
    uintptr_t unmapped = 0;
    if (findUnmappedAddress(&unmapped)) {
        expect(integrity::readSelfMemory(unmapped, buffer, sizeof(buffer)) ==
                   integrity::kStatusUnavailable,
               "reading an unmapped address reports unavailable rather than faulting");
    } else {
        std::printf("SKIPPED: no address could be shown to be unmapped, so the unmapped-read "
                    "property was not exercised\n");
    }

    expect(integrity::readSelfMemory(own, nullptr, 16) == integrity::kStatusInvalidInput,
           "a null destination is invalid input");
    expect(integrity::readSelfMemory(own, buffer, 0) == integrity::kStatusInvalidInput,
           "a zero length is invalid input");
    expect(integrity::readSelfMemory(own, buffer, integrity::kMaxSafeReadBytes + 1) ==
               integrity::kStatusInvalidInput,
           "an oversized length is refused rather than attempted");

    // The two branches mutation testing found unguarded: both are unreachable through
    // /proc/self/mem on a healthy process, so breaking either changed nothing observable.
    expect(integrity::readProcessMemory("/proc/self/no-such-file", own, buffer, 8) ==
               integrity::kStatusUnavailable,
           "a file that will not open is unavailable, never success");
    expect(integrity::readProcessMemory(nullptr, own, buffer, 8) ==
               integrity::kStatusInvalidInput,
           "a null path is invalid input");
    // /dev/null answers a read with zero bytes rather than an error, which is exactly the
    // short-read case: without the got == 0 check the loop would never make progress.
    expect(integrity::readProcessMemory("/dev/null", own, buffer, 8) ==
               integrity::kStatusUnavailable,
           "a read that returns nothing is a failure, not an empty success");
}

}  // namespace

int main() {
    buildTokenTests();
    validMappingTests();
    malformedMappingTests();
    unsafeRangeTests();
    safeReadTests();

    if (failures == 0) {
        // Printed so a 32-bit run is distinguishable from a 64-bit one in CI logs; the
        // overflow guards behave differently at each width and both must be exercised.
        std::printf("OK: native host tests passed (%zu-bit uintptr_t)\n",
                    sizeof(uintptr_t) * 8);
    }
    return failures == 0 ? 0 : 1;
}
