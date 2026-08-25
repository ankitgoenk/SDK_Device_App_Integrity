// Property and adversarial tests for the native parsing, validation and read paths.
//
// The named cases in native_host_test.cpp encode the failures we already know about. These
// look for the ones we do not, and they are judged by whether they kill mutants
// (tools/mutate-native.py), not by how many cases they run. Ten thousand inputs from a weak
// generator are worth less than two hundred near-misses; the volume here is free, so it is
// taken, but it is not the point.
//
// Deterministic by construction: a fixed seed, overridable as argv[1] so a CI failure can be
// reproduced exactly. A test that cannot be replayed is a rumour.
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdint.h>
#include <string>

#include "../maps.h"
#include "../safe_read.h"
#include "../selfcheck.h"

namespace {

int failures = 0;
int checks = 0;

void expect(bool condition, const char* what) {
    ++checks;
    if (!condition) {
        std::printf("FAIL: %s\n", what);
        ++failures;
    }
}

// ---------------------------------------------------------------------------
// Deterministic PRNG. xorshift64*, chosen because it is a dozen lines and needs no
// standard library support that ANDROID_STL=none would not have.
// ---------------------------------------------------------------------------
uint64_t rngState = 0x2545F4914F6CDD1Dull;

uint64_t nextRandom() {
    rngState ^= rngState >> 12;
    rngState ^= rngState << 25;
    rngState ^= rngState >> 27;
    return rngState * 2685821657736338717ull;
}

size_t randomBelow(size_t bound) {
    return bound == 0 ? 0 : static_cast<size_t>(nextRandom() % bound);
}

uintptr_t randomAddress() {
    // Weighted towards the boundaries, where the bugs live: the extremes of the address
    // space, the off_t sign boundary, and small values.
    switch (randomBelow(6)) {
        case 0: return 0;
        case 1: return UINTPTR_MAX;
        case 2: return UINTPTR_MAX - randomBelow(64);
        case 3: return (UINTPTR_MAX / 2) + 1 - randomBelow(64);
        case 4: return static_cast<uintptr_t>(randomBelow(4096));
        default: return static_cast<uintptr_t>(nextRandom());
    }
}

// ---------------------------------------------------------------------------
// Exact address+length arithmetic in a wider type, so the oracle does not restate the
// implementation's own overflow trick. An oracle that shares the bug proves nothing.
// ---------------------------------------------------------------------------
#if UINTPTR_MAX <= 0xffffffffu
typedef uint64_t WideAddress;
#else
typedef unsigned __int128 WideAddress;
#endif

bool wouldWrap(uintptr_t address, size_t length) {
    const WideAddress sum = static_cast<WideAddress>(address) + static_cast<WideAddress>(length);
    return sum > static_cast<WideAddress>(UINTPTR_MAX);
}

// ---------------------------------------------------------------------------
// An independent recogniser for the grammar parseMapsLine accepts, written from the
// /proc/self/maps format rather than from the parser. strtoull does the number conversion,
// so a shared bug would have to be the same mistake made twice in two different shapes.
// ---------------------------------------------------------------------------
bool oracleAccepts(const std::string& line, uintptr_t* outStart, uintptr_t* outEnd,
                   bool* readable, bool* writable, bool* executable) {
    const size_t dash = line.find('-');
    if (dash == std::string::npos || dash == 0) return false;
    for (size_t i = 0; i < dash; ++i) {
        if (!std::isxdigit(static_cast<unsigned char>(line[i]))) return false;
    }

    const size_t space = line.find(' ', dash + 1);
    if (space == std::string::npos || space == dash + 1) return false;
    for (size_t i = dash + 1; i < space; ++i) {
        if (!std::isxdigit(static_cast<unsigned char>(line[i]))) return false;
    }

    if (line.size() < space + 5) return false;
    const char r = line[space + 1];
    const char w = line[space + 2];
    const char x = line[space + 3];
    const char p = line[space + 4];
    if (r != 'r' && r != '-') return false;
    if (w != 'w' && w != '-') return false;
    if (x != 'x' && x != '-') return false;
    if (p != 'p' && p != 's') return false;

    errno = 0;
    const unsigned long long start = std::strtoull(line.substr(0, dash).c_str(), nullptr, 16);
    if (errno == ERANGE || start > static_cast<unsigned long long>(UINTPTR_MAX)) return false;
    errno = 0;
    const unsigned long long end =
        std::strtoull(line.substr(dash + 1, space - dash - 1).c_str(), nullptr, 16);
    if (errno == ERANGE || end > static_cast<unsigned long long>(UINTPTR_MAX)) return false;

    if (end < start) return false;

    *outStart = static_cast<uintptr_t>(start);
    *outEnd = static_cast<uintptr_t>(end);
    *readable = (r == 'r');
    *writable = (w == 'w');
    *executable = (x == 'x');
    return true;
}

// ---------------------------------------------------------------------------
// Generators
// ---------------------------------------------------------------------------
const char kHexDigits[] = "0123456789abcdefABCDEF";

std::string randomHex(size_t digits) {
    std::string out;
    for (size_t i = 0; i < digits; ++i) {
        out += kHexDigits[randomBelow(sizeof(kHexDigits) - 1)];
    }
    return out;
}

/**
 * Hex at and around the widest value the pointer can hold.
 *
 * Added because mutation testing killed the "overflow guard removed" mutant but not the
 * "overflow guard off by one" one: the generator produced addresses of at most twelve
 * digits, so the guard's actual boundary was never reached. A generator that never visits
 * the boundary cannot test the boundary check.
 */
std::string boundaryHex() {
    const size_t width = sizeof(uintptr_t) * 2;  // hex digits in a maximal address
    switch (randomBelow(4)) {
        case 0: return std::string(width, 'f');                       // exactly UINTPTR_MAX
        case 1: return std::string(width, 'f').substr(0, width - 1) + "e";
        case 2: return "1" + std::string(width, '0');                 // one digit too wide
        default: return std::string(width - 1, 'f');                  // just inside
    }
}

/** Uniform noise. Cheap, and its job is to prove nothing ever escapes as a status. */
std::string randomNoise() {
    std::string out;
    const size_t length = randomBelow(80);
    for (size_t i = 0; i < length; ++i) {
        out += static_cast<char>(randomBelow(256));
    }
    return out;
}

/**
 * A well-formed line with, usually, exactly one thing wrong with it.
 *
 * This is the generator that matters. Both real defects this project has hit came from
 * input that looked entirely reasonable until one field was off — a valid-looking range
 * that wrapped, a valid address too wide for the pointer. Uniform noise never produces
 * that shape.
 */
std::string randomNearMiss() {
    std::string start = randomBelow(3) == 0 ? boundaryHex() : randomHex(1 + randomBelow(12));
    std::string end = randomBelow(3) == 0 ? boundaryHex() : randomHex(1 + randomBelow(12));
    // The fourth permission character is p or s and nothing else. It gets a wider alphabet
    // here than the grammar allows, because a generator that only emits legal values cannot
    // tell a strict check from a lax one — mutation testing found exactly that gap.
    const char* kSharingAlphabet = "ps-x?";
    char perms[5] = {
        randomBelow(2) ? 'r' : '-',
        randomBelow(2) ? 'w' : '-',
        randomBelow(2) ? 'x' : '-',
        randomBelow(4) == 0 ? kSharingAlphabet[randomBelow(5)] : (randomBelow(2) ? 'p' : 's'),
        '\0',
    };
    std::string line = start + "-" + end + " " + perms + " 00000000 fd:00 1234 /lib/x.so";

    switch (randomBelow(10)) {
        case 0: return line;                                        // untouched
        case 1: return std::string(40, 'f') + "-" + end + " " + perms + " 0";
        case 2: return start + "-" + std::string(40, 'e') + " " + perms + " 0";
        case 3: {                                                   // corrupt one character
            if (line.empty()) return line;
            const size_t at = randomBelow(line.size());
            line[at] = static_cast<char>(randomBelow(256));
            return line;
        }
        case 4: return line.substr(0, randomBelow(line.size() + 1));  // truncate anywhere
        case 5: return start + " " + end + " " + perms + " 0";        // separator gone
        case 6: return start + "-" + " " + perms + " 0";              // end address gone
        case 7: return "-" + end + " " + perms + " 0";                // start address gone
        case 8: return end + "-" + start + " " + perms + " 0";        // possibly end < start
        default: return line + std::string(randomBelow(32), 'z');     // trailing junk
    }
}

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------
constexpr int kCases = 10000;

/** No input of any shape may produce anything but a known status. */
void statusIsAlwaysWellFormed() {
    for (int i = 0; i < kCases; ++i) {
        const std::string line = (i % 2 == 0) ? randomNoise() : randomNearMiss();
        integrity::MappedRange range{};
        const integrity::NativeStatus status =
            integrity::parseMapsLine(line.c_str(), line.size(), &range);

        const bool known = status == integrity::kStatusOk ||
                           status == integrity::kStatusInvalidInput ||
                           status == integrity::kStatusParseFailed;
        if (!known) {
            std::printf("FAIL: unknown status %d for input of length %zu\n",
                        static_cast<int>(status), line.size());
            ++failures;
            return;
        }
        ++checks;
    }
}

/** The parser agrees with an independently written recogniser, in both directions. */
void parserMatchesAnIndependentOracle() {
    for (int i = 0; i < kCases; ++i) {
        const std::string line = (i % 4 == 0) ? randomNoise() : randomNearMiss();
        if (line.empty()) continue;  // empty is kStatusInvalidInput by contract, not a parse

        integrity::MappedRange range{};
        const bool parsed =
            integrity::parseMapsLine(line.c_str(), line.size(), &range) == integrity::kStatusOk;

        uintptr_t start = 0;
        uintptr_t end = 0;
        bool r = false;
        bool w = false;
        bool x = false;
        const bool oracle = oracleAccepts(line, &start, &end, &r, &w, &x);

        if (parsed != oracle) {
            std::printf("FAIL: parser said %d, oracle said %d, for: %s\n",
                        static_cast<int>(parsed), static_cast<int>(oracle), line.c_str());
            ++failures;
            return;
        }
        if (parsed && (range.start != start || range.end != end || range.readable != r ||
                       range.writable != w || range.executable != x)) {
            std::printf("FAIL: parser and oracle disagree on the values for: %s\n", line.c_str());
            ++failures;
            return;
        }
        ++checks;
    }
}

/** A parsed range is never internally inconsistent, whatever the input was. */
void anAcceptedRangeIsNeverInverted() {
    for (int i = 0; i < kCases; ++i) {
        const std::string line = randomNearMiss();
        integrity::MappedRange range{};
        if (integrity::parseMapsLine(line.c_str(), line.size(), &range) != integrity::kStatusOk) {
            continue;
        }
        if (range.end < range.start) {
            std::printf("FAIL: accepted an inverted range from: %s\n", line.c_str());
            ++failures;
            return;
        }
        ++checks;
    }
}

/**
 * rangeIsReadable is a total specification, so both directions are checked: kStatusOk
 * exactly when the read is genuinely contained in a readable mapping and the arithmetic
 * does not wrap. A one-directional test lets a check that says "unavailable" to everything
 * pass, which is the collapse this project keeps meeting.
 */
void rangeValidationMatchesItsSpecification() {
    for (int i = 0; i < kCases; ++i) {
        const uintptr_t a = randomAddress();
        const uintptr_t b = randomAddress();
        const integrity::MappedRange range{
            a < b ? a : b,
            a < b ? b : a,
            randomBelow(2) == 0,
            randomBelow(2) == 0,
            randomBelow(2) == 0,
        };
        const uintptr_t address = randomAddress();
        const size_t length = randomBelow(2) ? randomBelow(96) : randomBelow(4096);

        const integrity::NativeStatus actual =
            integrity::rangeIsReadable(range, address, length);

        integrity::NativeStatus expected;
        if (length == 0 || wouldWrap(address, length)) {
            expected = integrity::kStatusInvalidInput;
        } else if (!range.readable || address < range.start ||
                   static_cast<WideAddress>(address) + length > range.end) {
            expected = integrity::kStatusUnavailable;
        } else {
            expected = integrity::kStatusOk;
        }

        if (actual != expected) {
            std::printf("FAIL: rangeIsReadable(addr=%llu len=%zu in [%llu,%llu) readable=%d)"
                        " gave %d, expected %d\n",
                        static_cast<unsigned long long>(address), length,
                        static_cast<unsigned long long>(range.start),
                        static_cast<unsigned long long>(range.end),
                        static_cast<int>(range.readable), static_cast<int>(actual),
                        static_cast<int>(expected));
            ++failures;
            return;
        }
        ++checks;
    }
}

/** Reads that cannot be satisfied are refused before anything is attempted. */
void impossibleReadsAreRefused() {
    unsigned char buffer[128];
    for (int i = 0; i < kCases; ++i) {
        const uintptr_t address = randomAddress();
        const size_t length = randomBelow(2)
            ? integrity::kMaxSafeReadBytes + 1 + randomBelow(1024)
            : randomBelow(64);

        const integrity::NativeStatus status =
            integrity::readSelfMemory(address, buffer, length);

        const bool mustRefuse = length == 0 || length > integrity::kMaxSafeReadBytes ||
                                wouldWrap(address, length);
        if (mustRefuse && status != integrity::kStatusInvalidInput) {
            std::printf("FAIL: readSelfMemory(len=%zu) returned %d, expected invalid input\n",
                        length, static_cast<int>(status));
            ++failures;
            return;
        }
        if (!mustRefuse && status == integrity::kStatusInvalidInput) {
            std::printf("FAIL: readSelfMemory(len=%zu) refused a satisfiable request\n", length);
            ++failures;
            return;
        }
        ++checks;
    }
}

/** Only the exact token verifies. Thousands of near-misses, none of which may pass. */
void onlyTheExactTokenVerifies() {
    const std::string token = integrity::buildToken();
    for (int i = 0; i < kCases; ++i) {
        std::string candidate = token;
        switch (randomBelow(5)) {
            case 0:
                if (candidate.empty()) continue;
                candidate[randomBelow(candidate.size())] =
                    static_cast<char>(1 + randomBelow(255));
                break;
            case 1: candidate = candidate.substr(0, randomBelow(candidate.size() + 1)); break;
            case 2: candidate += static_cast<char>(1 + randomBelow(255)); break;
            case 3: candidate = randomHex(randomBelow(24)); break;
            default:
                if (candidate.size() < 2) continue;
                std::swap(candidate[0], candidate[candidate.size() - 1]);
                break;
        }
        if (candidate == token) continue;

        if (integrity::verifyBuildToken(candidate.c_str()) == integrity::kOk) {
            std::printf("FAIL: '%s' verified as the build token\n", candidate.c_str());
            ++failures;
            return;
        }
        ++checks;
    }
    expect(integrity::verifyBuildToken(token.c_str()) == integrity::kOk,
           "the exact token still verifies after all that");
}

/**
 * The three pieces, tied together on this process's real mappings.
 *
 * Parsing, validating and reading can each be correct alone while the composition is
 * useless. This takes an address that certainly is mapped, finds it in the parser's own
 * output, and requires that the validator agrees and the read succeeds — the same relative
 * property that caught the off_t truncation, applied to the whole chain.
 */
void theChainAgreesOnRealMappings() {
    unsigned char onTheStack = 0;
    const uintptr_t target = reinterpret_cast<uintptr_t>(&onTheStack);

    std::FILE* maps = std::fopen("/proc/self/maps", "r");
    if (maps == nullptr) {
        std::printf("SKIPPED: /proc/self/maps unreadable, the chain property was not exercised\n");
        return;
    }

    char line[512];
    bool found = false;
    while (std::fgets(line, sizeof(line), maps) != nullptr) {
        const size_t length = std::strlen(line);
        integrity::MappedRange range{};
        if (integrity::parseMapsLine(line, length, &range) != integrity::kStatusOk) continue;
        if (target < range.start || target >= range.end) continue;

        found = true;
        expect(range.readable, "the mapping holding our own stack is readable");
        expect(integrity::rangeIsReadable(range, target, 1) == integrity::kStatusOk,
               "the validator agrees the stack address is readable");

        unsigned char byte = 0;
        expect(integrity::readSelfMemory(target, &byte, 1) == integrity::kStatusOk,
               "the read succeeds for an address the validator accepted");
        break;
    }
    std::fclose(maps);

    expect(found, "the parser found the mapping containing our own stack");
}

}  // namespace

int main(int argc, char** argv) {
    if (argc > 1) {
        rngState = std::strtoull(argv[1], nullptr, 0);
        if (rngState == 0) rngState = 1;  // xorshift is dead at zero
    }
    const uint64_t seed = rngState;

    statusIsAlwaysWellFormed();
    parserMatchesAnIndependentOracle();
    anAcceptedRangeIsNeverInverted();
    rangeValidationMatchesItsSpecification();
    impossibleReadsAreRefused();
    onlyTheExactTokenVerifies();
    theChainAgreesOnRealMappings();

    if (failures == 0) {
        std::printf("OK: %d property checks passed (%zu-bit uintptr_t, seed 0x%llx)\n",
                    checks, sizeof(uintptr_t) * 8, static_cast<unsigned long long>(seed));
        return 0;
    }
    std::printf("%d failure(s). Reproduce with: %s 0x%llx\n", failures, argv[0],
                static_cast<unsigned long long>(seed));
    return 1;
}
