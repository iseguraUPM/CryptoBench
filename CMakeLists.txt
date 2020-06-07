cmake_minimum_required(VERSION 3.10)
set(TARGET_NAME cryptobench)

project(${TARGET_NAME})

CMAKE_HOST_SYSTEM_INFORMATION(RESULT SYSTEM_MEMORY QUERY TOTAL_PHYSICAL_MEMORY)
add_definitions(-DHENCRYPT_SYS_MEMORY=${SYSTEM_MEMORY})
add_definitions(-DHENCRYPT_SYS_ARCH="${CMAKE_HOST_SYSTEM_PROCESSOR}")

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -D_GLIBCXX_USE_CXX11_ABI=1")

if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")
endif()

add_subdirectory(lib)

add_subdirectory(Google_test)

add_subdirectory(cryptoengine)

add_subdirectory(BenchmarkRunner)

add_subdirectory(src)



