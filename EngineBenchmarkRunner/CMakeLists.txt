project(engine-benchmark-runner)

add_definitions(-DCRYPTOBENCH_NO_RANDOM)

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_definitions(-DCRYPTOBENCH_DEBUG)
endif()

add_executable(engine-benchmark-runner main.cpp)
target_link_libraries(engine-benchmark-runner ${TARGET_NAME})