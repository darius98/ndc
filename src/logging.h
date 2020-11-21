#ifndef NDC_LOGGING_H_
#define NDC_LOGGING_H_

#include <stdio.h>
#include <stdlib.h>

void init_logging();

void internal_log_message(const char* filename, int lineno, const char* level, const char* fmt, ...)
    __attribute__((format(printf, 4, 5)));

// Default logging level is info. Logging level is only controlled at build time.
#ifndef NDC_LOG_LEVEL
#define NDC_LOG_LEVEL 1
#endif

// By default, log messages do not contain file name and line number. This is only controlled at build time.
#ifdef NDC_LOG_FILE_AND_LINE
#define INTERNAL_LOG_(level, ...) internal_log_message(__FILE__, __LINE__, level, __VA_ARGS__)
#else
#define INTERNAL_LOG_(level, ...) internal_log_message(0, 0, level, __ARGS__)
#endif

#if NDC_LOG_LEVEL <= 0
#define LOG_DEBUG(...) INTERNAL_LOG_("D", __VA_ARGS__)
#else
#define LOG_DEBUG(...) ((void)0)
#endif

#if NDC_LOG_LEVEL <= 1
#define LOG_INFO(...) INTERNAL_LOG_("I", __VA_ARGS__)
#else
#define LOG_INFO(...) ((void)0)
#endif

#if NDC_LOG_LEVEL <= 2
#define LOG_WARN(...) INTERNAL_LOG_("W", __VA_ARGS__)
#else
#define LOG_WARN(...) ((void)0)
#endif

#if NDC_LOG_LEVEL <= 3
#define LOG_ERROR(...) INTERNAL_LOG_("E", __VA_ARGS__)
#else
#define LOG_ERROR(...) ((void)0)
#endif

#define LOG_FATAL(...)                   \
    do {                                 \
        INTERNAL_LOG_("F", __VA_ARGS__); \
        abort();                         \
    } while (0)

#endif
