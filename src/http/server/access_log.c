#include "access_log.h"

#include <stdio.h>

#include "logging/logging.h"
#include "http_server.h"

void init_access_log(struct access_log* access_log, const char* access_log_desc) {
    ff_pthread_mutex_init(&access_log->file_lock, 0);
    set_log_file(access_log_desc, &access_log->file);
}

void log_access(struct http_req* req, int status) {
    struct access_log* access_log = &req->server->access_log;
    if (access_log->file != 0) {
        ff_pthread_mutex_lock(&access_log->file_lock);
        fprintf(access_log->file, "%s - - [", req_remote_ipv4(req));
        log_time(access_log->file);
        fprintf(access_log->file, "] \"%s %s %s\" %d\n", req_method(req), req_path(req), req_version(req), status);
        ff_pthread_mutex_unlock(&access_log->file_lock);
    }
}
