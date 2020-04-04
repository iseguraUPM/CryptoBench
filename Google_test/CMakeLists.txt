project(Google_test)

add_definitions(-DCRYPTOBENCH_NO_RANDOM)

set(BUILD_GMOCK "" ON)
set(INSTALL_GTEST "" OFF)
# 'lib' is the folder with Google Test sources
add_subdirectory(lib)
include_directories(${gtest_SOURCE_DIR}/include ${gmock_SOURCE_DIR}/include ${gmock_SOURCE_DIR} ${gtest_SOURCE_DIR} ../)

enable_testing()

# 'Google_Tests_run' is the target name
# 'test1.cpp tests2.cpp' are source files with tests
add_executable(Google_Tests_run gtest.cpp hello_world_test.cpp openssl_cipher_test.cpp cipher_factory_test.cpp cryptopp_cipher_test.cpp libsodium_cipher_test.cpp libgcrypt_cipher_test.cpp botan_cipher_test.cpp cipher_consistency_test.cpp cipher_factory_test.hpp cipher_avalanche_test.cpp cipher_avalanche_test.hpp wolfcrypt_cipher_test.cpp)
target_link_libraries(Google_Tests_run gtest gtest_main ${TARGET_NAME})