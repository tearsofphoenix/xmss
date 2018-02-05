cmake_minimum_required(VERSION 3.5)
project(xmss)

set(CMAKE_CXX_STANDARD 11)

include(CMakeHelpers.cmake)
include_directories(xmss-reference)

CheckLibrary()

add_library(xmss
        xmss-reference/params.c
        xmss-reference/hash.c
        xmss-reference/fips202.c
        xmss-reference/hash_address.c
        xmss-reference/randombytes.c
        xmss-reference/wots.c
        xmss-reference/xmss.c
        xmss-reference/xmss_core.c
        xmss-reference/xmss_commons.c
        xmss-reference/utils.c)

set_target_properties(xmss PROPERTIES
        ARCHIVE_OUTPUT_DIRECTORY "${PROJECT_SOURCE_DIR}/lib"
        LIBRARY_OUTPUT_DIRECTORY "${PROJECT_SOURCE_DIR}/lib"
        RUNTIME_OUTPUT_DIRECTORY "${PROJECT_SOURCE_DIR}/lib")