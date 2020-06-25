cmake_minimum_required(VERSION 3.4.1)
include(ExternalProject)

set(GPGERROR_PREFIX ${CMAKE_CURRENT_BINARY_DIR}/gpg-error CACHE INTERNAL "GPGERROR_PREFIX")
set(GPGERROR_SRC ${CMAKE_CURRENT_SOURCE_DIR}/lib)

ExternalProject_Add(libgpg-error
        SOURCE_DIR ${GPGERROR_SRC}/src
        CONFIGURE_COMMAND rm -f ${GPGERROR_SRC}/config.status && ${GPGERROR_SRC}/configure --with-pic --enable-maintainer-mode --prefix=${GPGERROR_PREFIX} --enable-static --enable-shared --libdir=${GPGERROR_PREFIX}/lib
        BUILD_COMMAND make && make install
        INSTALL_COMMAND make install
        BUILD_BYPRODUCTS ${GPGERROR_PREFIX}/lib/libgpg-error.a
        )

add_library(gpg-error STATIC IMPORTED GLOBAL)
add_dependencies(gpg-error libgpg-error)

file(MAKE_DIRECTORY ${GPGERROR_PREFIX}/include)
set_target_properties(gpg-error PROPERTIES IMPORTED_LOCATION ${GPGERROR_PREFIX}/lib/libgpg-error.a
        INTERFACE_INCLUDE_DIRECTORIES ${GPGERROR_PREFIX}/include)