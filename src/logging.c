#include "logging.h"

#include <pthread.h>
#include <stdarg.h>
#include <time.h>

static pthread_mutex_t logging_mutex;

void init_logging() {
    int err = pthread_mutex_init(&logging_mutex, 0);
    if (err != 0) {
        fprintf(stderr, "Failed to initialize logging mutex: pthread_mutex_init() error=%d\n", err);
        abort();
    }
}

void internal_log_message(const char* filename, int lineno, const char* level, const char* fmt, ...) {
    // Format is [YYYY-MM-DD HH:mm:ss], of length 21
    char tm_buffer[22];
    time_t timestamp;
    time(&timestamp);

    int err = pthread_mutex_lock(&logging_mutex);
    if (err != 0) {
        fprintf(stderr, "Failed to lock logging mutex: pthread_mutex_lock() error=%d\n", err);
        abort();
    }
    strftime(tm_buffer, 21, "[%F %T]", gmtime(&timestamp));
    tm_buffer[21] = 0;
    fprintf(stderr, "%s %s ", tm_buffer, level);
    if (filename != 0) {
        fprintf(stderr, "(%s:%d) ", filename, lineno);
    }
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    err = pthread_mutex_unlock(&logging_mutex);
    if (err != 0) {
        fprintf(stderr, "Failed to unlock logging mutex: pthread_mutex_unlock() error=%d\n", err);
        abort();
    }
}
