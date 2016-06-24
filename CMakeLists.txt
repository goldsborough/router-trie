###########################################################
## CMAKE SETUP
###########################################################

cmake_minimum_required(VERSION 3.2)
project(vector)

###########################################################
## DEPENDENCIES
###########################################################

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

add_subdirectory(vector)

###########################################################
## EXECUTABLES
###########################################################

add_executable(router-trie-test ${CMAKE_CURRENT_SOURCE_DIR}/test.c router-trie.c)

target_link_libraries(router-trie-test vector)

###########################################################
## COMPILER FLAGS
###########################################################

target_compile_options(router-trie-test PUBLIC -std=c99 -g)
