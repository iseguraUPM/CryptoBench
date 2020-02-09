set(LINK_LIBS ssl crypto)

add_library(${TARGET_NAME} library.cpp ../include/CryptoBench/symmetric_cipher.hpp openssl_cipher.cpp ../include/CryptoBench/openssl_cipher.hpp ../include/CryptoBench/secure_string.hpp aes_cipher.cpp ../include/CryptoBench/aes_cipher.hpp)
target_link_libraries(${TARGET_NAME} ${LINK_LIBS})
target_include_directories(${TARGET_NAME} PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_compile_options(${TARGET_NAME} PRIVATE -std=c++11)