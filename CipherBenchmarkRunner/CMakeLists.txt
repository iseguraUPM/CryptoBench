project(cipher-benchmark-runner)

add_definitions(-DHENCRYPT_NO_RANDOM)

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_definitions(-DHENCRYPT_DEBUG)
endif()

add_executable(cipher-benchmark-runner main.cpp byte_tools.hpp)
target_link_libraries(cipher-benchmark-runner ${TARGET_NAME})

