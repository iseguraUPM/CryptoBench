project(hencrypt-test)

add_definitions(-DHENCRYPT_NO_RANDOM)

enable_testing()

# 'Google_Tests_run' is the target name
# 'test1.cpp tests2.cpp' are source files with tests
add_executable(hencrypt-test gtest.cpp openssl_cipher_test.cpp cipher_factory_test.cpp cryptopp_cipher_test.cpp libsodium_cipher_test.cpp libgcrypt_cipher_test.cpp botan_cipher_test.cpp cipher_consistency_test.cpp cipher_factory_test.hpp cipher_avalanche_test.cpp cipher_avalanche_test.hpp wolfcrypt_cipher_test.cpp ortools_test.cpp engine_test.cpp library_test.cpp hencrypt_test.cpp codec_test.cpp cipher_database_test.cpp system_info_test.cpp)
target_link_libraries(hencrypt-test gtest gtest_main ${TARGET_NAME})