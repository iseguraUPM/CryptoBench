cmake_minimum_required(VERSION 3.4.1)
include(ExternalProject)

set(NACL_PREFIX ${CMAKE_CURRENT_BINARY_DIR}/libsodium)
set(NACL_SRC ${CMAKE_CURRENT_SOURCE_DIR}/lib)

if (LIBSODIUM_NO_OPTS)
    add_definitions(-DLIBSODIUM_DISABLE)
endif()

ExternalProject_Add(libsodium
        SOURCE_DIR ${NACL_SRC}/src/libsodium
        CONFIGURE_COMMAND rm -f ${NACL_SRC}/config.status && ${NACL_SRC}/configure --disable-pie --disable-shared --prefix=${NACL_PREFIX}
        BUILD_COMMAND make
        INSTALL_COMMAND make install
        BUILD_BYPRODUCTS ${NACL_PREFIX}/lib/libsodium.a
        #EXCLUDE_FROM_ALL TRUE
        )

add_library(nacl STATIC IMPORTED GLOBAL)
add_dependencies(nacl libsodium)

file(MAKE_DIRECTORY ${NACL_PREFIX}/include)
set_target_properties(nacl PROPERTIES IMPORTED_LOCATION ${NACL_PREFIX}/lib/libsodium.a
        INTERFACE_INCLUDE_DIRECTORIES ${NACL_PREFIX}/include)