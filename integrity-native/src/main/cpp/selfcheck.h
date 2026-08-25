// Pure, platform-independent half of the native core.
//
// Deliberately free of Android headers so it compiles and runs on a host toolchain too:
// logic that can only be exercised on a device is logic that will not be exercised.
#pragma once

namespace integrity {

enum SelfCheckStatus {
    kOk = 0,
    kTokenMismatch = 1,
    kBadArgument = 2,
};
// kProvokedFailure = 3 was the code the JNI catch block returned. Removed with the catch
// block: nothing here throws, so it could only ever have been reached by a bug that a
// catch(...) would not have contained anyway.

/** The build token compiled into this library. */
const char* buildToken();

/**
 * Compares the token the SDK expects against the one compiled into this library.
 *
 * A mismatch means the .so did not come from this build of the SDK — a swapped or stale
 * library. It is positive evidence about the artifact, unlike a failure to load at all,
 * which is indistinguishable from a missing ABI.
 */
SelfCheckStatus verifyBuildToken(const char* expected);

}  // namespace integrity
