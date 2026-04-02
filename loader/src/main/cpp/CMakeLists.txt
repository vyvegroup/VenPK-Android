cmake_minimum_required(VERSION 3.22.1)
project("venpk")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_VISIBILITY_PRESET hidden)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)

add_library(venpk SHARED
    venpk_jni.cpp
    venpk_crypto.cpp
    venpk_obfuscate.cpp
)

target_include_directories(venpk PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

find_library(log-lib log)

target_link_libraries(venpk
    ${log-lib}
)

# No external dependencies - pure C++ crypto implementation

# Optimization flags for release
target_compile_options(venpk PRIVATE
    -O2
    -fvisibility=hidden
    -ffunction-sections
    -fdata-sections
    -fstack-protector-strong
    -D_FORTIFY_SOURCE=2
)

# Strip symbols in release
if(CMAKE_BUILD_TYPE STREQUAL "Release" OR NOT CMAKE_BUILD_TYPE)
    target_link_options(venpk PRIVATE "-Wl,--gc-sections" "-Wl,--strip-all")
endif()
