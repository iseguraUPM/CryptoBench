cmake_minimum_required(VERSION 3.14)
include(ExternalProject)

set(ORTOOLS_PREFIX ${CMAKE_CURRENT_BINARY_DIR}/ortools)
set(ORTOOLS_SRC ${CMAKE_CURRENT_SOURCE_DIR}/lib)

file(MAKE_DIRECTORY ${ORTOOLS_PREFIX}/lib)

ExternalProject_Add(libortools
        SOURCE_DIR ${ORTOOLS_SRC}
        CMAKE_ARGS -DBUILD_DEPS=ON -DCMAKE_INSTALL_PREFIX=${ORTOOLS_PREFIX}
        BUILD_COMMAND make
        INSTALL_COMMAND make install
        )

add_library(ortools SHARED IMPORTED GLOBAL)
add_dependencies(ortools libortools)

file(MAKE_DIRECTORY ${ORTOOLS_PREFIX}/include)
set_target_properties(ortools PROPERTIES IMPORTED_LOCATION ${ORTOOLS_PREFIX}/lib/${CMAKE_SHARED_LIBRARY_PREFIX}ortools${CMAKE_SHARED_LIBRARY_SUFFIX}
        INTERFACE_INCLUDE_DIRECTORIES ${ORTOOLS_PREFIX}/include)