cmake_minimum_required(VERSION 3.10)
set(TARGET_NAME cryptobench)

project(${TARGET_NAME})

add_subdirectory(src)

add_subdirectory(Google_test)

add_subdirectory(BenchmarkRunner)

set(SYSTEM_OPENSSL OFF)
set(BUILD_OPENSSL ON)
set(OPENSSL_BUILD_VERSION 1.1.1d)
add_subdirectory(OpenSSL-CMake)