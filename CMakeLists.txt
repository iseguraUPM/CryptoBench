cmake_minimum_required(VERSION 3.10)
set(TARGET_NAME cryptobench)

project(${TARGET_NAME})

set(SYSTEM_OPENSSL OFF)
set(BUILD_OPENSSL ON)
set(OPENSSL_BRANCH OpenSSL_1_1_1d)
set(OPENSSL_BUILD_VERSION 1.1.1d)
add_subdirectory(OpenSSL-CMake)

add_subdirectory(Google_test)

add_subdirectory(BenchmarkRunner)

add_subdirectory(src)



