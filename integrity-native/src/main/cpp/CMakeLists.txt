cmake_minimum_required(VERSION 3.22.1)
project(integrity CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Supplied by Gradle so the library can identify which build of the SDK it belongs to.
if(NOT DEFINED INTEGRITY_TOKEN)
    message(FATAL_ERROR "INTEGRITY_TOKEN must be provided by the Gradle build")
endif()

add_library(integrity SHARED
        integrity.cpp
        maps.cpp
        safe_read.cpp
        selfcheck.cpp
        selftext.cpp)

target_compile_definitions(integrity PRIVATE
        INTEGRITY_BUILD_TOKEN="${INTEGRITY_TOKEN}")

target_compile_options(integrity PRIVATE
        -Wall -Wextra -Werror
        # No exception runtime: nothing here throws, and the fault that phase 3b risks was
        # never catchable by one. Every failure travels as a [[nodiscard]] NativeStatus.
        -fno-exceptions
        -fvisibility=hidden
        -ffunction-sections
        -fdata-sections)

# Strip aggressively: the release .so should give up nothing to `strings` or `nm`, and CI
# asserts that rather than trusting it (ADR-0002).
target_link_options(integrity PRIVATE
        -Wl,--gc-sections
        -Wl,--exclude-libs,ALL
        # 16 KB page support. NDK r27 still links at a 4 KB max-page-size, so without this
        # every LOAD segment is aligned 0x1000 and the library will not load on a 16 KB-page
        # device. An Android 16 Pixel raised exactly that warning against this .so.
        #
        # A linker option, not a compile one: passing it through cppFlags reaches clang as a
        # compile argument, which -Werror rejects as unused.
        #
        # This is a distribution property rather than a detection one, and it is not ours to
        # get wrong quietly: an SDK ships inside someone else's app, so every consumer
        # inherits the alignment we link with.
        -Wl,-z,max-page-size=16384)

set_target_properties(integrity PROPERTIES
        CXX_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN ON)
