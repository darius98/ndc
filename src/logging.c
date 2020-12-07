#include "logging.h"

#include <arpa/inet.h>
#include <errno.h>
#include <execinfo.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "ff_pthread.h"
#include "http_server.h"
#include "tcp_server.h"

static struct {
    FILE* access_file;
    FILE* server_log;
    int min_level;
    int log_filename_and_lineno;
    pthread_mutex_t lock;
    char level_name[5];
    char tm_buffer[20];  // Format is YYYY-MM-DD HH:mm:ss, of length 20
    char ipv4_str_buf[INET_ADDRSTRLEN];
} logging;

static void log_backtrace(int fd) {
    void* trace[32];
    int sz = backtrace(trace, 32);
    backtrace_symbols_fd(trace, sz, fd);
}

static void handle_signal_log_fatal(int sig) {
    if (logging.server_log != 0) {
        fprintf(logging.server_log, "Killed by signal %d\n", sig);
        if (fflush(logging.server_log) != 0) {
            fprintf(logging.server_log, "fflush() failed errno=%d (%s)", errno, strerror(errno));
        }
        log_backtrace(fileno(logging.server_log));
    }
    exit(128 + sig);
}

static void set_log_file(const char* desc, FILE** file) {
    if (strncasecmp(desc, "null", 4) == 0) {
        *file = 0;
    } else if (strncasecmp(desc, "stderr", 6) == 0) {
        *file = stderr;
    } else if (strncasecmp(desc, "stdout", 6) == 0) {
        *file = stdout;
    } else {
        *file = fopen(desc, "a");
        if (*file == 0) {
            fprintf(stderr, "Failed to open logging file '%s': errno=%d (%s)\n", desc, errno, strerror(errno));
            exit(EXIT_FAILURE);
        }
    }
}

void init_logging(const struct logging_conf* conf) {
    set_log_file(conf->access_log, &logging.access_file);
    set_log_file(conf->server_log, &logging.server_log);
    logging.min_level = conf->min_level;
    logging.log_filename_and_lineno = conf->filename_and_lineno;
    int err = pthread_mutex_init(&logging.lock, 0);
    if (err != 0) {
        if (logging.server_log != 0) {
            fprintf(logging.server_log, "Failed to initialize logging mutex: pthread_mutex_init() error=%d\n", err);
        }
        exit(EXIT_FAILURE);
    }
    logging.level_name[LOG_LEVEL_DEBUG] = 'D';
    logging.level_name[LOG_LEVEL_INFO] = 'I';
    logging.level_name[LOG_LEVEL_WARN] = 'W';
    logging.level_name[LOG_LEVEL_ERROR] = 'E';
    logging.level_name[LOG_LEVEL_FATAL] = 'F';
    logging.tm_buffer[19] = 0;
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
        if (logging.server_log != 0) {
            fprintf(logging.server_log, "Failed to lock logging mutex: pthread_mutex_lock() error=%d\n", err);
        }
        abort();
    }
}

void internal_log_unlock() {
    int err = pthread_mutex_unlock(&logging.lock);
    if (err != 0) {
        if (logging.server_log != 0) {
            fprintf(logging.server_log, "Failed to unlock logging mutex: pthread_mutex_unlock() error=%d\n", err);
        }
        abort();
    }
}

static void log_time(FILE* fp) {
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    strftime(logging.tm_buffer, 19, "%F %T", gmtime(&now.tv_sec));
    fprintf(fp, "%s.%03ld", logging.tm_buffer, now.tv_nsec / 1000000);
}

void internal_log_message(const char* filename, int lineno, int level, const char* fmt, ...) {
    if (logging.server_log != 0) {
        fprintf(logging.server_log, "[");
        log_time(logging.server_log);
        fprintf(logging.server_log, "] %c ", logging.level_name[level]);
        if (logging.log_filename_and_lineno != 0 && filename != 0) {
            fprintf(logging.server_log, "(%s:%d) ", filename, lineno);
        }
        va_list args;
        va_start(args, fmt);
        vfprintf(logging.server_log, fmt, args);
        fprintf(logging.server_log, "\n");
    }
}

void internal_log_die() {
    if (logging.server_log != 0) {
        if (fflush(logging.server_log) != 0) {
            fprintf(logging.server_log, "fflush() failed errno=%d (%s)", errno, strerror(errno));
        }
        log_backtrace(fileno(logging.server_log));
    }
    abort();
}

const char* ipv4_str(int ipv4) {
    inet_ntop(AF_INET, &ipv4, logging.ipv4_str_buf, INET_ADDRSTRLEN);
    return logging.ipv4_str_buf;
}

void log_access(struct http_req* req, int status) {
    if (logging.access_file != 0) {
        internal_log_lock();
        fprintf(logging.access_file, "%s - - [", ipv4_str(req->conn->ipv4));
        log_time(logging.access_file);
        fprintf(logging.access_file, "] \"%s %s %s\" %d\n", req->method, req->path, req->version, status);
        internal_log_unlock();
    }
}
