#include "ff_pthread.h"

#include "../logging/logging.h"

static void fail_fast(const char* func, int ret) {
    if (ret != 0) {
        LOG_FATAL("%s failed, returned %d", func, ret);
    }
}

void ff_pthread_create(pthread_t* t, pthread_attr_t* a, void* (*entry)(void*), void* arg) {
    fail_fast("pthread_create", pthread_create(t, a, entry, arg));
}

void ff_pthread_mutex_init(pthread_mutex_t* m, pthread_mutexattr_t* a) {
    fail_fast("pthread_mutex_init", pthread_mutex_init(m, a));
}

void ff_pthread_mutex_lock(pthread_mutex_t* m) {
    fail_fast("pthread_mutex_lock", pthread_mutex_lock(m));
}

void ff_pthread_mutex_unlock(pthread_mutex_t* m) {
    fail_fast("pthread_mutex_unlock", pthread_mutex_unlock(m));
}

void ff_pthread_cond_init(pthread_cond_t* c, pthread_condattr_t* a) {
    fail_fast("pthread_cond_init", pthread_cond_init(c, a));
}

void ff_pthread_cond_signal(pthread_cond_t* c) {
    fail_fast("pthread_cond_signal", pthread_cond_signal(c));
}

void ff_pthread_cond_wait(pthread_cond_t* c, pthread_mutex_t* m) {
    fail_fast("pthread_cond_wait", pthread_cond_wait(c, m));
}
