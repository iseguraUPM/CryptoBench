set(TARGET_NAME CryptoBench)

set(LINK_LIBS ssl crypto)

add_library(${TARGET_NAME} library.cpp)
target_link_libraries(${TARGET_NAME} ${LINK_LIBS})
target_include_directories(${TARGET_NAME} PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_compile_options(${TARGET_NAME} PRIVATE -std=c++11)