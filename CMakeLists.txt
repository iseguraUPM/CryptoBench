cmake_minimum_required(VERSION 3.15)
set(TARGET_NAME hencrypt)

project(${TARGET_NAME})

CMAKE_HOST_SYSTEM_INFORMATION(RESULT SYSTEM_MEMORY QUERY TOTAL_PHYSICAL_MEMORY)
add_definitions(-DHENCRYPT_SYS_MEMORY=${SYSTEM_MEMORY})
add_definitions(-DHENCRYPT_SYS_ARCH="${CMAKE_HOST_SYSTEM_PROCESSOR}")

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -D_GLIBCXX_USE_CXX11_ABI=1 -fPIC")

if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")
endif()

add_subdirectory(lib)

add_subdirectory(test)

add_subdirectory(CipherBenchmarkRunner)

add_subdirectory(EngineBenchmarkRunner)

add_subdirectory(src)



