#include "logging.h"

#include <pthread.h>
#include <time.h>

static pthread_mutexattr_t logging_mutex_attr;
static pthread_mutex_t logging_mutex;

void init_logging() {
    pthread_mutexattr_init(&logging_mutex_attr);
    pthread_mutex_init(&logging_mutex, &logging_mutex_attr);
}

void acquire_log_mutex() {
    pthread_mutex_lock(&logging_mutex);
}

void log_formatted_time() {
    // Format is [YYYY-MM-DD HH:mm:ss], of length 21
    char buffer[22];
    time_t timestamp;
    time(&timestamp);
    strftime(buffer, 21, "[%F %T]", gmtime(&timestamp));
    buffer[21] = 0;
    fprintf(stderr, "%s", buffer);
}

void release_log_mutex() {
    pthread_mutex_unlock(&logging_mutex);
}
