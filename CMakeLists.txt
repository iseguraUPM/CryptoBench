cmake_minimum_required(VERSION 3.10)
set(TARGET_NAME cryptobench)

project(${TARGET_NAME})

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -D_GLIBCXX_USE_CXX11_ABI=0")

if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libstdc++")
endif()

set(SYSTEM_OPENSSL OFF CACHE BOOL "Use system OpenSSL" FORCE)
set(BUILD_OPENSSL ON CACHE BOOL "Build own OpenSSL" FORCE)
set(OPENSSL_BRANCH OpenSSL_1_1_1d CACHE STRING "OpenSSL Git branch" FORCE)
set(OPENSSL_BUILD_VERSION 1.1.1d CACHE STRING "OpenSSL version" FORCE)
add_subdirectory(OpenSSL-CMake)

add_subdirectory(cryptopp-8.2)

add_subdirectory(libsodium-1.0.18)

add_subdirectory(libgpg-error-1.37)

add_subdirectory(libgcrypt-1.8.5)

add_subdirectory(Botan-2.13.0)

add_subdirectory(wolfSSL-4.3.0)

add_subdirectory(Google_test)

add_subdirectory(BenchmarkRunner)

add_subdirectory(src)



