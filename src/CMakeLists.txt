set(LINK_LIBS ssl crypto pthread dl cryptopp nacl gcrypt gpg-error botan)

add_library(${TARGET_NAME} library.cpp ../include/CryptoBench/symmetric_cipher.hpp openssl_cipher.cpp ../include/CryptoBench/openssl_cipher.hpp ../include/CryptoBench/secure_string.hpp open_ssl_cipher_factory.cpp ../include/CryptoBench/open_ssl_cipher_factory.hpp ../include/CryptoBench/cipher_factory.hpp ../include/CryptoBench/random_bytes.hpp libsodium_cipher_factory.cpp ../include/CryptoBench/libsodium_cipher_factory.hpp cryptopp_cipher_factory.cpp ../include/CryptoBench/cryptopp_cipher_factory.hpp libgcrypt_cipher_factory.cpp ../include/CryptoBench/libgcrypt_cipher_factory.hpp)
target_link_libraries(${TARGET_NAME} ${LINK_LIBS})
target_include_directories(${TARGET_NAME} PUBLIC ${CMAKE_SOURCE_DIR}/include)
#target_compile_options(${TARGET_NAME} PRIVATE -std=gnu++11)