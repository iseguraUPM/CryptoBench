project(cryptoengine)

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_definitions(-DCRYPTOBENCH_DEBUG)
endif()

add_definitions(-g2 -O3)

file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/res/)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/gen/)

set(BENCHMARK_DATA ${CMAKE_CURRENT_SOURCE_DIR}/benchmark_${CMAKE_HOST_SYSTEM_PROCESSOR}.csv)

if (NOT EXISTS ${BENCHMARK_DATA})
    MESSAGE(FATAL_ERROR "Missing cryptography statistics for ${CMAKE_HOST_SYSTEM_PROCESSOR} (file ${BENCHMARK_DATA} not found)")
endif()

add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/gen/cryptoengine.cpp
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/cryptoengine.cpp.template ${BENCHMARK_DATA}
        COMMAND python ${CMAKE_CURRENT_SOURCE_DIR}/decision_tree_generator.py ${CMAKE_CURRENT_SOURCE_DIR}/benchmark_x86_64.csv ${CMAKE_CURRENT_SOURCE_DIR}/block_cipher_rounds.csv ${CMAKE_CURRENT_SOURCE_DIR}/cryptoengine.cpp.template ${CMAKE_CURRENT_BINARY_DIR}/gen/cryptoengine.cpp)

set(cryptoengine_PREFIX ${CMAKE_CURRENT_BINARY_DIR}/cryptoengine)

add_library(cryptoengine STATIC ${CMAKE_CURRENT_BINARY_DIR}/gen/cryptoengine.cpp cryptoengine.hpp)

target_include_directories(cryptoengine PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        DESTINATION ${cryptopp_PREFIX}/include
        FILES_MATCHING PATTERN "*.h*")

install(TARGETS cryptoengine
        ARCHIVE DESTINATION ${cryptoengine_PREFIX}/obj
        LIBRARY DESTINATION ${cryptoengine_PREFIX}/lib
        PUBLIC_HEADER DESTINATION ${cryptoengine_PREFIX}/include)