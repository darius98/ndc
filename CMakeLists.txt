cmake_minimum_required(VERSION 3.16)
project(ndc C CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 11)

add_executable(ndc
        src/http.c
        src/logging.c
        src/main.c
        src/static_file_server.c
        src/tcp_conn_table.c
        src/tcp_server.c)
target_compile_options(ndc PRIVATE -Wall -Wextra -Wpedantic)
if (CMAKE_BUILD_TYPE STREQUAL "Release")
    message(STATUS "Using LTO for release build")
    target_compile_options(ndc PUBLIC -flto)
    target_link_options(ndc PUBLIC -flto)
else ()
    target_compile_definitions(ndc PUBLIC -DNDC_LOG_FILE_AND_LINE -DNDC_LOG_LEVEL=0)
    message(STATUS "Using address sanitizer for debug build")
    target_compile_options(ndc PUBLIC -fsanitize=address)
    target_link_options(ndc PUBLIC -fsanitize=address)
endif()
