cmake_minimum_required(VERSION 3.4.1)
include(ExternalProject)

set(WOLFSSL_PREFIX ${CMAKE_CURRENT_BINARY_DIR}/libwolfssl)
set(WOLFSSL_SRC ${CMAKE_CURRENT_SOURCE_DIR}/lib)

ExternalProject_Add(libwolfssl
        SOURCE_DIR ${WOLFSSL_SRC}
        PREFIX ${WOLFSSL_PREFIX}
        CONFIGURE_COMMAND rm -f ${WOLFSSL_SRC}/config.status && ${WOLFSSL_SRC}/configure --prefix=${WOLFSSL_PREFIX} --enable-shared --enable-static  --enable-harden --enable-aescbc --enable-aesctr --enable-camellia --enable-aesgcm --enable-aesccm --enable-ecc --enable-des3 --enable-xts
        BUILD_COMMAND make
        INSTALL_COMMAND make install
        BUILD_BYPRODUCTS ${WOLFSSL_PREFIX}/lib/libwolfssl.a
        #EXCLUDE_FROM_ALL TRUE
        )

add_library(wolfssl STATIC IMPORTED GLOBAL)
add_dependencies(wolfssl libwolfssl)

file(MAKE_DIRECTORY ${WOLFSSL_PREFIX}/include)
set_target_properties(wolfssl PROPERTIES IMPORTED_LOCATION ${WOLFSSL_PREFIX}/lib/libwolfssl.a
        INTERFACE_INCLUDE_DIRECTORIES ${WOLFSSL_SRC})