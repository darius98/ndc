cmake_minimum_required(VERSION 3.16)
project(ndc C CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 11)

include(CheckIncludeFiles)
check_include_files("sys/event.h" USE_KQUEUE)
check_include_files("sys/epoll.h" USE_EPOLL)

set(ndc_sources
        src/file_cache.c
        src/http_server.c
        src/logging.c
        src/main.c
        src/static_file_server.c
        src/tcp_server.c
        src/write_queue.c)
if (USE_KQUEUE)
    message(STATUS "Using kqueue for tcp loop")
    list(APPEND ndc_sources
            src/tcp_server_kqueue.c
            src/write_worker_loop_kqueue.c)
elseif (USE_EPOLL)
    message(STATUS "Using epoll for tcp loop")
    list(APPEND ndc_sources
            src/tcp_server_epoll.c
            src/write_worker_loop_epoll.c)
else ()
    message(FATAL_ERROR "No suitable backend for tcp loop (kqueue and epoll are supported)")
endif()

add_executable(ndc ${ndc_sources})
target_compile_options(ndc PRIVATE -Wall -Wextra -Wpedantic)
if (CMAKE_BUILD_TYPE STREQUAL "Release")
    message(STATUS "Using LTO for release build")
    target_compile_options(ndc PUBLIC -flto)
    target_link_options(ndc PUBLIC -flto)
else ()
    target_compile_definitions(ndc PUBLIC -DNDC_LOG_FILE_AND_LINE -DNDC_LOG_LEVEL=0)
    message(STATUS "Using address & UB sanitizers for debug build")
    target_compile_options(ndc PUBLIC -fsanitize=address,undefined)
    target_link_options(ndc PUBLIC -fsanitize=address,undefined)
endif()
