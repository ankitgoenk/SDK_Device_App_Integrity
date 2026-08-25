#include "selfcheck.h"

#ifndef INTEGRITY_BUILD_TOKEN
#define INTEGRITY_BUILD_TOKEN "unset"
#endif

namespace integrity {
namespace {

// Length-independent comparison. Not a security boundary here — an attacker with the
// library can read the token — but the habit belongs in this file rather than being
// retrofitted once it does matter.
bool equalsConstantTime(const char* a, const char* b) {
    unsigned char difference = 0;
    while (*a != '\0' && *b != '\0') {
        difference |= static_cast<unsigned char>(*a++) ^ static_cast<unsigned char>(*b++);
    }
    difference |= static_cast<unsigned char>(*a) ^ static_cast<unsigned char>(*b);
    return difference == 0;
}

}  // namespace

const char* buildToken() {
    return INTEGRITY_BUILD_TOKEN;
}

SelfCheckStatus verifyBuildToken(const char* expected) {
    if (expected == nullptr) {
        return kBadArgument;
    }
    return equalsConstantTime(expected, buildToken()) ? kOk : kTokenMismatch;
}

}  // namespace integrity
