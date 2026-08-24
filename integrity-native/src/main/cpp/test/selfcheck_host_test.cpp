// Host-runnable test of the pure native logic.
//
// The device tests prove the library loads and the JNI boundary works; this proves the
// logic inside it is right, without needing an emulator. Built and run by CI on the host
// toolchain, so a regression here is caught in seconds rather than minutes.
#include <cstddef>
#include <cstdio>
#include <cstring>

#include <string>

#include "../selfcheck.h"

namespace {

int failures = 0;

void expect(bool condition, const char* what) {
    if (!condition) {
        std::printf("FAIL: %s\n", what);
        ++failures;
    }
}

}  // namespace

int main() {
    expect(integrity::verifyBuildToken(integrity::buildToken()) == integrity::kOk,
           "the compiled-in token verifies against itself");
    expect(integrity::verifyBuildToken("not-the-token") == integrity::kTokenMismatch,
           "a different token is a mismatch");
    expect(integrity::verifyBuildToken("") == integrity::kTokenMismatch,
           "an empty token is a mismatch");
    expect(integrity::verifyBuildToken(nullptr) == integrity::kBadArgument,
           "a null token is rejected rather than dereferenced");

    // A prefix of the real token must not pass: a comparison that stops at the shorter
    // string would accept it. Derived from the token itself rather than a fixed length,
    // because a fixed length silently stops testing anything for a short token.
    const char* token = integrity::buildToken();
    const std::size_t length = std::strlen(token);
    if (length > 1) {
        std::string prefix(token, length - 1);
        expect(integrity::verifyBuildToken(prefix.c_str()) == integrity::kTokenMismatch,
               "a prefix of the real token is a mismatch");

        std::string extended = std::string(token) + "x";
        expect(integrity::verifyBuildToken(extended.c_str()) == integrity::kTokenMismatch,
               "the real token with a suffix is a mismatch");
    } else {
        std::printf("FAIL: build token is too short to test meaningfully\n");
        ++failures;
    }

    if (failures == 0) {
        std::printf("OK: native self-check host tests passed\n");
    }
    return failures == 0 ? 0 : 1;
}
