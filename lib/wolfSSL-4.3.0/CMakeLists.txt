cmake_minimum_required(VERSION 3.4.1)
include(ExternalProject)

set(WOLFSSL_PREFIX ${CMAKE_CURRENT_BINARY_DIR}/libwolfssl)
set(WOLFSSL_SRC ${CMAKE_CURRENT_SOURCE_DIR}/lib)
set(WOLFSSL_CONF_ARGS  --enable-harden --enable-aescbc --enable-aesctr --enable-camellia --enable-aesgcm --enable-aesccm --enable-ecc --enable-des3 --enable-xts)
if (WOLFSSL_CROSS_ARM)
    set(WOLFSSL_CONF_ARGS ${WOLFSSL_CONF_ARGS} --enable-asn)
elseif(NOT WOLFSSL_NO_OPTS)
    set(WOLFSSL_CONF_ARGS ${WOLFSSL_CONF_ARGS} --enable-rng --enable-aesni --enable-intelasm --enable-asn --enable-fastmath)
endif()
ExternalProject_Add(libwolfssl
        SOURCE_DIR ${WOLFSSL_SRC}
        PREFIX ${WOLFSSL_PREFIX}
        CONFIGURE_COMMAND rm -f ${WOLFSSL_SRC}/config.status && ${WOLFSSL_SRC}/configure --with-pic --prefix=${WOLFSSL_PREFIX} --enable-shared --enable-static ${WOLFSSL_CONF_ARGS}
        BUILD_COMMAND ${CMAKE_MAKE_PROGRAM}
        INSTALL_COMMAND ${CMAKE_MAKE_PROGRAM} install
        BUILD_BYPRODUCTS ${WOLFSSL_PREFIX}/lib/libwolfssl.a
        #EXCLUDE_FROM_ALL TRUE
        )

add_library(wolfssl STATIC IMPORTED GLOBAL)
add_dependencies(wolfssl libwolfssl)


file(MAKE_DIRECTORY ${WOLFSSL_PREFIX}/include)
set_target_properties(wolfssl PROPERTIES IMPORTED_LOCATION ${WOLFSSL_PREFIX}/lib/libwolfssl.a
        INTERFACE_INCLUDE_DIRECTORIES ${WOLFSSL_PREFIX}/include)