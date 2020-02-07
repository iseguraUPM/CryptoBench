cmake_minimum_required(VERSION 3.10)
set(TARGET_NAME cryptobench)

project(${TARGET_NAME})

add_subdirectory(src)

add_subdirectory(Google_test)