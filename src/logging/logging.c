#include "logging.h"

#include <arpa/inet.h>
#include <errno.h>
#include <execinfo.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static struct {
    FILE* file;
    int min_level;
    int log_filename_and_lineno;
    pthread_mutex_t lock;
    char level_name[5];
} logging;

static void log_backtrace(int fd) {
    void* trace[32];
    int sz = backtrace(trace, 32);
    backtrace_symbols_fd(trace, sz, fd);
}

static void handle_signal_log_fatal(int sig) {
    if (logging.file != 0) {
        fprintf(logging.file, "Killed by signal %d\n", sig);
        if (fflush(logging.file) != 0) {
            fprintf(logging.file, "fflush() failed errno=%d (%s)", errno, errno_str(errno));
        }
        log_backtrace(fileno(logging.file));
    }
    exit(128 + sig);
}

void set_log_file(const char* desc, FILE** file) {
    if (strncasecmp(desc, "null", 4) == 0) {
        *file = 0;
    } else if (strncasecmp(desc, "stderr", 6) == 0) {
        *file = stderr;
    } else if (strncasecmp(desc, "stdout", 6) == 0) {
        *file = stdout;
    } else {
        *file = fopen(desc, "a");
        if (*file == 0) {
            fprintf(stderr, "Failed to open logging file '%s': errno=%d (%s)\n", desc, errno, errno_str(errno));
            exit(EXIT_FAILURE);
        }
    }
}

void init_logging(const struct logging_conf* conf) {
    set_log_file(conf->server_log, &logging.file);
    logging.min_level = conf->min_level;
    logging.log_filename_and_lineno = conf->filename_and_lineno;
    int err = pthread_mutex_init(&logging.lock, 0);
    if (err != 0) {
        if (logging.file != 0) {
            fprintf(logging.file, "Failed to initialize logging mutex: pthread_mutex_init() error=%d\n", err);
        }
        exit(EXIT_FAILURE);
    }
    logging.level_name[LOG_LEVEL_DEBUG] = 'D';
    logging.level_name[LOG_LEVEL_INFO] = 'I';
    logging.level_name[LOG_LEVEL_WARN] = 'W';
    logging.level_name[LOG_LEVEL_ERROR] = 'E';
    logging.level_name[LOG_LEVEL_FATAL] = 'F';

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

static void lock_logs() {
    int err = pthread_mutex_lock(&logging.lock);
    if (err != 0) {
        if (logging.file != 0) {
            fprintf(logging.file, "Failed to lock logging mutex: pthread_mutex_lock() error=%d\n", err);
        }
        abort();
    }
}

static void unlock_logs() {
    int err = pthread_mutex_unlock(&logging.lock);
    if (err != 0) {
        if (logging.file != 0) {
            fprintf(logging.file, "Failed to unlock logging mutex: pthread_mutex_unlock() error=%d\n", err);
        }
        abort();
    }
}

static __thread char tm_buffer[20];  // Format is YYYY-MM-DD HH:mm:ss, of length 20
void log_time(FILE* fp) {
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    strftime(tm_buffer, 19, "%F %T", gmtime(&now.tv_sec));
    fprintf(fp, "%s.%03ld", tm_buffer, now.tv_nsec / 1000000);
}

static __thread char strerror_buf[256];
const char* errno_str(int err) {
    strerror_r(err, strerror_buf, 256);
    return strerror_buf;
}

static __thread char ipv4_str_buf[INET_ADDRSTRLEN];
const char* ipv4_str(uint32_t ipv4) {
    inet_ntop(AF_INET, &ipv4, ipv4_str_buf, INET_ADDRSTRLEN);
    return ipv4_str_buf;
}

static void log_msg_preamble(const char* filename, int lineno, int level) {
    fprintf(logging.file, "[");
    log_time(logging.file);
    fprintf(logging.file, "] %c ", logging.level_name[level]);
    if (logging.log_filename_and_lineno != 0 && filename != 0) {
        fprintf(logging.file, "(%s:%d) ", filename, lineno);
    }
}

#define LOG_MSG_BODY(file, fmt) \
    va_list args;               \
    va_start(args, fmt);        \
    vfprintf(file, fmt, args);  \
    fprintf(file, "\n")

void internal_log_message(const char* filename, int lineno, int level, const char* fmt, ...) {
    if (logging.file == 0) {
        return;
    }
    lock_logs();
    log_msg_preamble(filename, lineno, level);
    LOG_MSG_BODY(logging.file, fmt);
    unlock_logs();
}

void internal_log_fatal_message(const char* filename, int lineno, int level, const char* fmt, ...) {
    if (logging.file == 0) {
        abort();
    }
    lock_logs();
    log_msg_preamble(filename, lineno, level);
    LOG_MSG_BODY(logging.file, fmt);
    if (fflush(logging.file) != 0) {
        fprintf(logging.file, "fflush() failed errno=%d (%s)\n", errno, errno_str(errno));
    }
    log_backtrace(fileno(logging.file));
    abort();
}
