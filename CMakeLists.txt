cmake_minimum_required(VERSION 3.16)
project(ndc C CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 11)

include(CheckIncludeFiles)
check_include_files("sys/event.h" USE_KQUEUE)
check_include_files("sys/epoll.h" USE_EPOLL)

if (CMAKE_BUILD_TYPE STREQUAL "Release")
    message(STATUS "Using LTO for release build")
else ()
    message(STATUS "Using address & UB sanitizers for non-release build")
endif ()

function(apply_ndc_target_opts TARGET)
    target_compile_options(${TARGET} PRIVATE -Wall -Wextra -Wpedantic)
    target_include_directories(${TARGET} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    if (CMAKE_BUILD_TYPE STREQUAL "Release")
        target_compile_options(${TARGET} PRIVATE -flto)
        target_link_options(${TARGET} PRIVATE -flto)
    else ()
        target_compile_definitions(${TARGET} PRIVATE -DNDC_LOG_FILE_AND_LINE -DNDC_LOG_LEVEL=0)
        target_compile_options(${TARGET} PRIVATE -fsanitize=address,undefined)
        target_link_options(${TARGET} PRIVATE -fsanitize=address,undefined)
    endif ()
endfunction()

function(add_ndc_library TARGET)
    add_library(${TARGET} ${ARGN})
    apply_ndc_target_opts(${TARGET})
endfunction()

function(add_ndc_executable TARGET)
    add_executable(${TARGET} ${ARGN})
    apply_ndc_target_opts(${TARGET})
endfunction()

set(ndc_event_loop_sources src/event_loop/event_loop.c)
if (USE_KQUEUE)
    message(STATUS "Using kqueue for event loop")
    list(APPEND ndc_event_loop_sources src/event_loop/event_loop_kqueue.c)
elseif (USE_EPOLL)
    message(STATUS "Using epoll for event loop")
    list(APPEND ndc_event_loop_sources src/event_loop/event_loop_epoll.c)
else ()
    message(FATAL_ERROR "No suitable backend for event loop implementation (kqueue and epoll are supported)")
endif ()
add_ndc_library(ndc_event_loop STATIC ${ndc_event_loop_sources})

add_ndc_library(ndc_conf STATIC
        src/conf/conf.c)

add_ndc_library(ndc_utils STATIC
        src/utils/fd.c
        src/utils/ff_pthread.c)

add_ndc_library(ndc_logging STATIC
        src/logging/logging.c)

add_ndc_library(ndc_tcp STATIC
        src/tcp/tcp_conn.c
        src/tcp/tcp_server.c
        src/tcp/tls.c)
target_link_libraries(ndc_tcp PUBLIC
        ndc_event_loop
        ndc_logging
        ndc_utils)
# Compile options for the OpenSSL dependency
if (APPLE)
    message(STATUS "On MacOS, assuming OpenSSL was installed using brew into /usr/local/opt/openssl/")
    target_include_directories(ndc_tcp PRIVATE /usr/local/opt/openssl/include)
    target_link_directories(ndc_tcp PUBLIC /usr/local/opt/openssl/lib)
    target_link_libraries(ndc_tcp PUBLIC ssl PUBLIC crypto)
else ()
    message(STATUS "On Linux, assuming OpenSSL was installed to a known location")
    target_link_libraries(ndc_tcp PUBLIC ssl PUBLIC crypto)
endif ()

add_ndc_library(ndc_http
        src/http/handlers/static_files/file_cache.c
        src/http/handlers/static_files/static_files_handler.c
        src/http/server/access_log.c
        src/http/server/http_req.c
        src/http/server/http_server.c)
target_link_libraries(ndc_http PUBLIC
        ndc_logging
        ndc_tcp)

add_ndc_executable(ndc src/main.c)
target_link_libraries(ndc PUBLIC
        ndc_conf
        ndc_logging
        ndc_utils
        ndc_http)
