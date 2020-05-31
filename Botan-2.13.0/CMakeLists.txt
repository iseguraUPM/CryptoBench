cmake_minimum_required(VERSION 3.4.1)
project(botan)
include(ExternalProject)

set(BOTAN_SRC ${CMAKE_CURRENT_SOURCE_DIR}/lib)
set(BOTAN_PREFIX ${CMAKE_CURRENT_BINARY_DIR}/botan)


set(BOTAN_CONF_ARGS)
if (BOTAN_CROSS_ARM)
    set(BOTAN_CONF_ARGS ${BOTAN_CONF_ARGS} --disable-sse2 --disable-ssse3 --disable-sse4.1 --disable-sse4.2 --disable-avx2 --disable-bmi2 --disable-rdrand --disable-rdseed --disable-aes-ni --disable-sha-ni --disable-altivec --disable-neon)
elseif(BOTAN_NO_OPTS)
    set(BOTAN_CONF_ARGS ${BOTAN_CONF_ARGS} --disable-sse2 --disable-ssse3 --disable-sse4.1 --disable-sse4.2 --disable-avx2 --disable-bmi2 --disable-rdrand --disable-rdseed --disable-aes-ni --disable-sha-ni --disable-altivec --disable-neon --disable-armv8crypto)
endif()


ExternalProject_Add(libbotan
        #GIT_REPOSITORY    https://github.com/randombit/botan.git
        #GIT_TAG           master
        #BASE_DIR          ${CMAKE_CURRENT_BINARY_DIR}/botan
        SOURCE_DIR        ${BOTAN_SRC}/src/lib

        CONFIGURE_COMMAND ${BOTAN_SRC}/configure.py --prefix=${BOTAN_PREFIX} --enable-static-library ${BOTAN_CONF_ARGS}
        BUILD_COMMAND     ${MAKE}
        INSTALL_COMMAND   make install
        BUILD_BYPRODUCTS  ${BOTAN_PREFIX}/lib/libbotan-2.a
)

add_library(botan STATIC IMPORTED GLOBAL)
add_dependencies(botan libbotan)

file(MAKE_DIRECTORY ${BOTAN_PREFIX}/include/botan-2)
set_target_properties(botan PROPERTIES IMPORTED_LOCATION ${BOTAN_PREFIX}/lib/libbotan-2.a
        INTERFACE_INCLUDE_DIRECTORIES ${BOTAN_PREFIX}/include/botan-2)