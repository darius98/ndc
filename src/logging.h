#ifndef NDC_LOGGING_H_
#define NDC_LOGGING_H_

void init_logging(int log_filename_and_lineno, int min_level);

extern int internal_log_min_level;

void internal_log_lock();

void internal_log_unlock();

void internal_log_message(const char* filename, int lineno, int level, const char* fmt, ...)
    __attribute__((format(printf, 4, 5)));

__attribute__((noreturn)) void internal_log_die();

const char* ipv4_str(int ipv4);

// Default logging level is info.
#ifndef NDC_LOG_LEVEL
#define NDC_LOG_LEVEL 1
#endif

// By default, log messages do not contain file name and line number.
#ifdef NDC_LOG_FILE_AND_LINE
#define INTERNAL_LOG_(level, ...)                                     \
    if (internal_log_min_level <= level) {                            \
        internal_log_lock();                                          \
        internal_log_message(__FILE__, __LINE__, level, __VA_ARGS__); \
        internal_log_unlock();                                        \
    }
#else
#define INTERNAL_LOG_(level, ...)                       \
    if (internal_log_min_level <= level) {              \
        internal_log_lock();                            \
        internal_log_message(0, 0, level, __VA_ARGS__); \
        internal_log_unlock();                          \
    }
#endif

#if NDC_LOG_LEVEL <= 0
#define LOG_DEBUG(...)                \
    do {                              \
        INTERNAL_LOG_(0, __VA_ARGS__) \
    } while (0)
#else
#define LOG_DEBUG(...) ((void)0)
#endif

#if NDC_LOG_LEVEL <= 1
#define LOG_INFO(...)                 \
    do {                              \
        INTERNAL_LOG_(1, __VA_ARGS__) \
    } while (0)
#else
#define LOG_INFO(...) ((void)0)
#endif

#if NDC_LOG_LEVEL <= 2
#define LOG_WARN(...)                 \
    do {                              \
        INTERNAL_LOG_(2, __VA_ARGS__) \
    } while (0)
#else
#define LOG_WARN(...) ((void)0)
#endif

#if NDC_LOG_LEVEL <= 3
#define LOG_ERROR(...)                \
    do {                              \
        INTERNAL_LOG_(3, __VA_ARGS__) \
    } while (0)
#else
#define LOG_ERROR(...) ((void)0)
#endif

#define LOG_FATAL(...)                \
    do {                              \
        INTERNAL_LOG_(4, __VA_ARGS__) \
        internal_log_die();           \
    } while (0)

#define ASSERT(c)                                     \
    do {                                              \
        if (!(c)) {                                   \
            INTERNAL_LOG_(4, "Assertion failed: " #c) \
            internal_log_die();                       \
        }                                             \
    } while (0)

#define ASSERT_0(expr)                                                                \
    do {                                                                              \
        int EXPR_RESULT = (expr);                                                     \
        if (EXPR_RESULT != 0) {                                                       \
            INTERNAL_LOG_(4, "Assertion failed: " #expr " == 0 (is %d)", EXPR_RESULT) \
            internal_log_die();                                                       \
        }                                                                             \
    } while (0)

#endif
