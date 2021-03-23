#ifndef NDC_HTTP_SERVER_ACCESS_LOG_H_
#define NDC_HTTP_SERVER_ACCESS_LOG_H_

#include "utils/config.h"

#include "http_req.h"
#include "utils/ff_pthread.h"

#include <stdio.h>

NDC_BEGIN_DECLS

struct access_log {
    FILE* file;
    pthread_mutex_t file_lock;
};

void init_access_log(struct access_log* access_log, const char* access_log_desc);

void log_access(struct http_req* req, int status);

NDC_END_DECLS

#endif
