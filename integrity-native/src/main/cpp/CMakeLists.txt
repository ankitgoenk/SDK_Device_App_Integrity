cmake_minimum_required(VERSION 3.22.1)
project(integrity)

add_library(integrity SHARED
        integrity.cpp)

find_library(log-lib log)
target_link_libraries(integrity ${log-lib})

# Strip aggressively; the release .so should give up nothing to `strings` or `nm`.
target_link_options(integrity PRIVATE
        -Wl,--gc-sections
        -Wl,--exclude-libs,ALL
        -Wl,-z,defs)

set_target_properties(integrity PROPERTIES
        C_VISIBILITY_PRESET hidden
        CXX_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN ON
        INTERPROCEDURAL_OPTIMIZATION TRUE)
