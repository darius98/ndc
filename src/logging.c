#include "logging.h"

#include <arpa/inet.h>
#include <execinfo.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static struct {
    int min_level;
    int log_filename_and_lineno;
    pthread_mutex_t lock;
    char level_name[5];
    char tm_buffer[21];  // Format is [YYYY-MM-DD HH:mm:ss, of length 20
    char ipv4_str_buf[INET_ADDRSTRLEN];
} logging;

static void internal_log_backtrace() {
    void* trace[32];
    int sz = backtrace(trace, 32);
    backtrace_symbols_fd(trace, sz, 2);
}

static void handle_signal_log_fatal(int sig) {
    fprintf(stderr, "Killed by signal %d\n", sig);
    internal_log_backtrace();
    exit(128 + sig);
}

void init_logging(int log_filename_and_lineno, int min_level) {
    logging.min_level = min_level;
    logging.log_filename_and_lineno = log_filename_and_lineno;
    int err = pthread_mutex_init(&logging.lock, 0);
    if (err != 0) {
        fprintf(stderr, "Failed to initialize logging mutex: pthread_mutex_init() error=%d\n", err);
        abort();
    }
    logging.level_name[LOG_LEVEL_DEBUG] = 'D';
    logging.level_name[LOG_LEVEL_INFO] = 'I';
    logging.level_name[LOG_LEVEL_WARN] = 'W';
    logging.level_name[LOG_LEVEL_ERROR] = 'E';
    logging.level_name[LOG_LEVEL_FATAL] = 'F';
    logging.tm_buffer[20] = 0;
    logging.ipv4_str_buf[INET_ADDRSTRLEN - 1] = 0;

    // Install signal handlers
    signal(SIGBUS, handle_signal_log_fatal);
    signal(SIGFPE, handle_signal_log_fatal);
    signal(SIGHUP, handle_signal_log_fatal);
    signal(SIGILL, handle_signal_log_fatal);
    signal(SIGINT, handle_signal_log_fatal);
    signal(SIGQUIT, handle_signal_log_fatal);
    signal(SIGSEGV, handle_signal_log_fatal);
    signal(SIGSYS, handle_signal_log_fatal);
    signal(SIGTERM, handle_signal_log_fatal);
    signal(SIGUSR1, handle_signal_log_fatal);
    signal(SIGUSR2, handle_signal_log_fatal);
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
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    strftime(logging.tm_buffer, 20, "[%F %T", gmtime(&now.tv_sec));
    fprintf(stderr, "%s.%03ld] %c ", logging.tm_buffer, now.tv_nsec / 1000000, logging.level_name[level]);
    if (logging.log_filename_and_lineno != 0 && filename != 0) {
        fprintf(stderr, "(%s:%d) ", filename, lineno);
    }
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
}

void internal_log_die() {
    internal_log_backtrace();
    abort();
}

const char* ipv4_str(int ipv4) {
    inet_ntop(AF_INET, &ipv4, logging.ipv4_str_buf, INET_ADDRSTRLEN);
    return logging.ipv4_str_buf;
}
