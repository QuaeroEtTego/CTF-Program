cmake_minimum_required(VERSION 3.22.1)
project(CTF-Program C)

set(CMAKE_C_STANDARD 11)

find_package(OpenSSL REQUIRED)

add_executable(program main.c)
target_link_libraries(program OpenSSL::SSL)