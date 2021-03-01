#ifndef NDC_UTILS_FF_PTHREAD_H_
#define NDC_UTILS_FF_PTHREAD_H_

#include <pthread.h>

#include "utils/config.h"

NDC_BEGIN_DECLS

void ff_pthread_create(pthread_t* t, pthread_attr_t* a, void* (*entry)(void*), void* arg);

void ff_pthread_mutex_init(pthread_mutex_t* m, pthread_mutexattr_t* a);

void ff_pthread_mutex_lock(pthread_mutex_t* m);

void ff_pthread_mutex_unlock(pthread_mutex_t* m);

void ff_pthread_cond_init(pthread_cond_t* c, pthread_condattr_t* a);

void ff_pthread_cond_signal(pthread_cond_t* c);

void ff_pthread_cond_wait(pthread_cond_t* c, pthread_mutex_t* m);

NDC_END_DECLS

#endif
