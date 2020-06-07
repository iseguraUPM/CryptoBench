project(Google_test)

set(BUILD_GMOCK "" ON)
set(INSTALL_GTEST "" OFF)
# 'lib' is the folder with Google Test sources
add_subdirectory(lib)
include_directories(${gtest_SOURCE_DIR}/include ${gmock_SOURCE_DIR}/include ${gmock_SOURCE_DIR} ${gtest_SOURCE_DIR} ../)