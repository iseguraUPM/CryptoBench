project(benchmark-runner)

add_definitions(-DCRYPTOBENCH_NO_RANDOM)

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_definitions(-DCRYPTOBENCH_DEBUG)
endif()

add_executable(benchmark-runner main.cpp byte_tools.hpp)
target_link_libraries(benchmark-runner ${TARGET_NAME})

