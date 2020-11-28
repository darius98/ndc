#include "logging.h"

#include <arpa/inet.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static struct {
    int min_level;
    int log_filename_and_lineno;
    pthread_mutex_t lock;
    const char* level_name[5];
    char tm_buffer[22];  // Format is [YYYY-MM-DD HH:mm:ss], of length 21
    char ipv4_str_buf[INET_ADDRSTRLEN];
} logging;

void init_logging(int log_filename_and_lineno, int min_level) {
    logging.min_level = min_level;
    logging.log_filename_and_lineno = log_filename_and_lineno;
    int err = pthread_mutex_init(&logging.lock, 0);
    if (err != 0) {
        fprintf(stderr, "Failed to initialize logging mutex: pthread_mutex_init() error=%d\n", err);
        abort();
    }
    logging.level_name[0] = "D";
    logging.level_name[1] = "I";
    logging.level_name[2] = "W";
    logging.level_name[3] = "E";
    logging.level_name[4] = "F";
    logging.tm_buffer[21] = 0;
    logging.ipv4_str_buf[INET_ADDRSTRLEN - 1] = 0;
}

int internal_log_min_level() {
    return logging.min_level;
}

void internal_log_lock() {
    int err = pthread_mutex_lock(&logging.lock);
    if (err != 0) {
        fprintf(stderr, "Failed to lock logging mutex: pthread_mutex_lock() error=%d\n", err);
        abort();
    }
}

void internal_log_unlock() {
    int err = pthread_mutex_unlock(&logging.lock);
    if (err != 0) {
        fprintf(stderr, "Failed to unlock logging mutex: pthread_mutex_unlock() error=%d\n", err);
        abort();
    }
}

void internal_log_message(const char* filename, int lineno, int level, const char* fmt, ...) {
    time_t timestamp;
    time(&timestamp);
    strftime(logging.tm_buffer, 21, "[%F %T]", gmtime(&timestamp));
    fprintf(stderr, "%s %s ", logging.tm_buffer, logging.level_name[level]);
    if (logging.log_filename_and_lineno != 0 && filename != 0) {
        fprintf(stderr, "(%s:%d) ", filename, lineno);
    }
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
}

void internal_log_die() {
    abort();
}

const char* ipv4_str(int ipv4) {
    inet_ntop(AF_INET, &ipv4, logging.ipv4_str_buf, INET_ADDRSTRLEN);
    return logging.ipv4_str_buf;
}
