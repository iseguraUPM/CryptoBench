cmake_minimum_required(VERSION 3.10)
set(TARGET_NAME cryptobench)

project(${TARGET_NAME})

set(SYSTEM_OPENSSL OFF CACHE BOOL "Use system OpenSSL" FORCE)
set(BUILD_OPENSSL ON CACHE BOOL "Build own OpenSSL" FORCE)
set(OPENSSL_BRANCH OpenSSL_1_1_1d CACHE STRING "OpenSSL Git branch" FORCE)
set(OPENSSL_BUILD_VERSION 1.1.1d CACHE STRING "OpenSSL version" FORCE)
add_subdirectory(OpenSSL-CMake)

add_subdirectory(Google_test)

add_subdirectory(BenchmarkRunner)

add_subdirectory(src)



