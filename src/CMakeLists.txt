set(LINK_LIBS ssl crypto pthread dl)

add_library(${TARGET_NAME} library.cpp ../include/CryptoBench/symmetric_cipher.hpp openssl_cipher.cpp ../include/CryptoBench/openssl_cipher.hpp ../include/CryptoBench/secure_string.hpp open_ssl_cipher_factory.cpp ../include/CryptoBench/open_ssl_cipher_factory.hpp)
target_link_libraries(${TARGET_NAME} ${LINK_LIBS})
target_include_directories(${TARGET_NAME} PUBLIC ${CMAKE_SOURCE_DIR}/include)
#target_compile_options(${TARGET_NAME} PRIVATE -std=gnu++11)