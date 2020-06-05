project(cipher-tree-test)

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_definitions(-DCRYPTOBENCH_DEBUG)
endif()

file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/res/)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/gen/)

add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/gen/cipher_decision_tree.c
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/cipher_decision_tree.c.template
        COMMAND python ${CMAKE_CURRENT_SOURCE_DIR}/TreeMaker.py ${CMAKE_CURRENT_SOURCE_DIR}/benchmark.csv ${CMAKE_CURRENT_SOURCE_DIR}/block_cipher_rounds.csv ${CMAKE_CURRENT_SOURCE_DIR}/cipher_decision_tree.c.template ${CMAKE_CURRENT_BINARY_DIR}/gen/cipher_decision_tree.c)

set_source_files_properties(${OBJS}
        PROPERTIES
        EXTERNAL_OBJECT true
        GENERATED true)
add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/res/cipher_decision_tree.o
        DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/gen/cipher_decision_tree.c
        COMMAND cp ${CMAKE_CURRENT_SOURCE_DIR}/cipher_decision_tree.h ${CMAKE_CURRENT_BINARY_DIR}/gen/cipher_decision_tree.h && ${CMAKE_CXX_COMPILER} -g -O -c ${CMAKE_CURRENT_BINARY_DIR}/gen/cipher_decision_tree.c -o ${CMAKE_CURRENT_BINARY_DIR}/res/cipher_decision_tree.o)

set(OBJS ${CMAKE_CURRENT_BINARY_DIR}/res/cipher_decision_tree.o)

add_executable(cipher-tree-test decision_tree_test.cpp cipher_decision_tree.h ${OBJS})