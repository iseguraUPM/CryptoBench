cmake_minimum_required(VERSION 3.4.1)
include(ExternalProject)

set(GCRYPT_PREFIX ${CMAKE_CURRENT_BINARY_DIR}/gcrypt)
set(GCRYPTL_SRC ${CMAKE_CURRENT_SOURCE_DIR}/lib)

file(MAKE_DIRECTORY ${GCRYPT_PREFIX}/lib)

if (GCRYPT_NO_OPTS)
    add_definitions(-DGCRYPT_NO_OPTS)
endif()

ExternalProject_Add(libgcrypt
        SOURCE_DIR ${GCRYPTL_SRC}/src
        CONFIGURE_COMMAND rm -f ${GCRYPTL_SRC}/config.status && touch ${GCRYPTL_SRC}/doc/version.texi && touch ${GCRYPTL_SRC}/doc/version-remake.texi && ${GCRYPTL_SRC}/configure --prefix=${GCRYPT_PREFIX} --enable-static --enable-shared --libdir=${GCRYPT_PREFIX}/lib --with-gpg-error-prefix=${GPGERROR_PREFIX} --with-libgpg-error-prefix=${GPGERROR_PREFIX}/lib
        BUILD_COMMAND make && make install
        INSTALL_COMMAND make install
        BUILD_BYPRODUCTS ${GCRYPT_PREFIX}/lib/libgcrypt.a
        #EXCLUDE_FROM_ALL TRUE
        )

add_library(gcrypt STATIC IMPORTED GLOBAL)
add_dependencies(gcrypt gpg-error libgcrypt)
link_libraries(gpg-error)

file(MAKE_DIRECTORY ${GCRYPT_PREFIX}/include)
set_target_properties(gcrypt PROPERTIES IMPORTED_LOCATION ${GCRYPT_PREFIX}/lib/libgcrypt.a
        INTERFACE_INCLUDE_DIRECTORIES ${GCRYPT_PREFIX}/include)