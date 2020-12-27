cmake_minimum_required(VERSION 3.16)
project(ndc C CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 11)

include(CheckIncludeFiles)
check_include_files("sys/event.h" USE_KQUEUE)
check_include_files("sys/epoll.h" USE_EPOLL)

set(ndc_sources
        src/app.c
        src/conf.c
        src/fd.c
        src/ff_pthread.c
        src/file_cache.c
        src/http_req.c
        src/http_server.c
        src/logging.c
        src/main.c
        src/tls.c
        src/static_file_server.c
        src/tcp_server.c
        src/write_queue.c)
if (USE_KQUEUE)
    message(STATUS "Using kqueue for tcp loop")
    list(APPEND ndc_sources
            src/tcp_server_kqueue.c
            src/write_queue_kqueue.c)
elseif (USE_EPOLL)
    message(STATUS "Using epoll for tcp loop")
    list(APPEND ndc_sources
            src/tcp_server_epoll.c
            src/write_queue_epoll.c)
else ()
    message(FATAL_ERROR "No suitable backend for tcp loop (kqueue and epoll are supported)")
endif()

add_executable(ndc ${ndc_sources})
target_compile_options(ndc PRIVATE -Wall -Wextra -Wpedantic)
if (CMAKE_BUILD_TYPE STREQUAL "Release")
    message(STATUS "Using LTO for release build")
    target_compile_options(ndc PRIVATE -flto)
    target_link_options(ndc PRIVATE -flto)
else ()
    target_compile_definitions(ndc PRIVATE -DNDC_LOG_FILE_AND_LINE -DNDC_LOG_LEVEL=0)
    message(STATUS "Using address & UB sanitizers for debug build")
    target_compile_options(ndc PRIVATE -fsanitize=address,undefined)
    target_link_options(ndc PRIVATE -fsanitize=address,undefined)
endif()

# Compile options for the OpenSSL dependency
if (APPLE)
    message(STATUS "On MacOS, assuming OpenSSL was installed using brew into /usr/local/opt/openssl/")
    target_include_directories(ndc PRIVATE /usr/local/opt/openssl/include)
    target_link_directories(ndc PRIVATE /usr/local/opt/openssl/lib)
    target_link_libraries(ndc PRIVATE ssl PRIVATE crypto)
else ()
    message(STATUS "On Linux, assuming OpenSSL was installed to a known location")
    target_link_libraries(ndc PRIVATE ssl PRIVATE crypto)
endif ()
