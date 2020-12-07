#ifndef NDC_LOGGING_H_
#define NDC_LOGGING_H_

#include "conf.h"

#define LOG_LEVEL_DEBUG 0
#define LOG_LEVEL_INFO 1
#define LOG_LEVEL_WARN 2
#define LOG_LEVEL_ERROR 3
#define LOG_LEVEL_FATAL 4

void init_logging(const struct logging_conf* conf);

struct http_req;
void log_access(struct http_req* req, int status);

int internal_log_min_level();

void internal_log_lock();

void internal_log_unlock();

void internal_log_message(const char* filename, int lineno, int level, const char* fmt, ...)
    __attribute__((format(printf, 4, 5)));

__attribute__((noreturn)) void internal_log_die();

const char* ipv4_str(int ipv4);

// Default logging level is info.
#ifndef NDC_LOG_LEVEL
#define NDC_LOG_LEVEL LOG_LEVEL_INFO
#endif

// By default, log messages do not contain file name and line number.
#ifdef NDC_LOG_FILE_AND_LINE
#define NDC_CURRENT_FILE (__builtin_strrchr(__FILE__, '/') ? __builtin_strrchr(__FILE__, '/') + 1 : __FILE__)
#define INTERNAL_LOG_MSG(level, ...)                                          \
    if (internal_log_min_level() <= level) {                                  \
        internal_log_lock();                                                  \
        internal_log_message(NDC_CURRENT_FILE, __LINE__, level, __VA_ARGS__); \
        internal_log_unlock();                                                \
    }
#else
#define INTERNAL_LOG_MSG(level, ...)                    \
    if (internal_log_min_level() <= level) {            \
        internal_log_lock();                            \
        internal_log_message(0, 0, level, __VA_ARGS__); \
        internal_log_unlock();                          \
    }
#endif

#if NDC_LOG_LEVEL <= LOG_LEVEL_DEBUG
#define LOG_DEBUG(...)                                 \
    do {                                               \
        INTERNAL_LOG_MSG(LOG_LEVEL_DEBUG, __VA_ARGS__) \
    } while (0)
#else
#define LOG_DEBUG(...) ((void)0)
#endif

#if NDC_LOG_LEVEL <= LOG_LEVEL_INFO
#define LOG_INFO(...)                                 \
    do {                                              \
        INTERNAL_LOG_MSG(LOG_LEVEL_INFO, __VA_ARGS__) \
    } while (0)
#else
#define LOG_INFO(...) ((void)0)
#endif

#if NDC_LOG_LEVEL <= LOG_LEVEL_WARN
#define LOG_WARN(...)                                 \
    do {                                              \
        INTERNAL_LOG_MSG(LOG_LEVEL_WARN, __VA_ARGS__) \
    } while (0)
#else
#define LOG_WARN(...) ((void)0)
#endif

#if NDC_LOG_LEVEL <= LOG_LEVEL_ERROR
#define LOG_ERROR(...)                                 \
    do {                                               \
        INTERNAL_LOG_MSG(LOG_LEVEL_ERROR, __VA_ARGS__) \
    } while (0)
#else
#define LOG_ERROR(...) ((void)0)
#endif

#define LOG_FATAL(...)                                 \
    do {                                               \
        INTERNAL_LOG_MSG(LOG_LEVEL_FATAL, __VA_ARGS__) \
        internal_log_die();                            \
    } while (0)

#endif
