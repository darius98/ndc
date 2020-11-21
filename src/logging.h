#ifndef NDC_LOGGING_H_
#define NDC_LOGGING_H_

#include <stdio.h>
#include <stdlib.h>

void init_logging();

void acquire_log_mutex();

void log_formatted_time();

void release_log_mutex();

// Default logging level is info. Logging level is only controlled at build time.
#ifndef NDC_LOG_LEVEL
#define NDC_LOG_LEVEL 1
#endif

// By default, log messages do not contain file name and line number. This is only controlled at build time.
#ifdef NDC_LOG_FILE_AND_LINE
#define INTERNAL_LOG_FILE_AND_LINE_() fprintf(stderr, " (%s:%d) ", __FILE__, __LINE__)
#else
#define INTERNAL_LOG_FILE_AND_LINE_() ((void)0)
#endif

#define INTERNAL_LOG_(level, ...)  \
    acquire_log_mutex();           \
    log_formatted_time();          \
    fprintf(stderr, " " level);    \
    INTERNAL_LOG_FILE_AND_LINE_(); \
    fprintf(stderr, __VA_ARGS__);  \
    fprintf(stderr, "\n");         \
    release_log_mutex()

#if NDC_LOG_LEVEL <= 0
#define LOG_DEBUG(...)                   \
    do {                                 \
        INTERNAL_LOG_("D", __VA_ARGS__); \
    } while (0)
#else
#define LOG_DEBUG(...) ((void)0)
#endif

#if NDC_LOG_LEVEL <= 1
#define LOG_INFO(...)                    \
    do {                                 \
        INTERNAL_LOG_("I", __VA_ARGS__); \
    } while (0)
#else
#define LOG_INFO(...) ((void)0)
#endif

#if NDC_LOG_LEVEL <= 2
#define LOG_WARN(...)                    \
    do {                                 \
        INTERNAL_LOG_("W", __VA_ARGS__); \
    } while (0)
#else
#define LOG_WARN(...) ((void)0)
#endif

#if NDC_LOG_LEVEL <= 3
#define LOG_ERROR(...)                   \
    do {                                 \
        INTERNAL_LOG_("E", __VA_ARGS__); \
    } while (0)
#else
#define LOG_ERROR(...) ((void)0)
#endif

#define LOG_FATAL(...)                   \
    do {                                 \
        INTERNAL_LOG_("F", __VA_ARGS__); \
        abort();                         \
    } while (0)

#endif
