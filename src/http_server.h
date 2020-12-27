#ifndef NDC_HTTP_SERVER_H_
#define NDC_HTTP_SERVER_H_

#include "conf.h"
#include "ff_pthread.h"
#include "http_req.h"

struct http_server {
    struct http_req* head;
    struct http_req* tail;

    pthread_mutex_t lock;
    pthread_cond_t cond_var;
    _Atomic(int) stopped;

    void* cb_data;

    int req_buf_cap;

    int num_workers;
    pthread_t* workers;
};

/// Initialize a http server. Note: Aborts on failure.
void init_http_server(struct http_server* server, const struct http_conf* conf);

void delete_http_req(struct http_server* server, struct http_req* req);

// These callbacks are not implemented in the HTTP server.

void on_http_req_callback(void* cb_data, struct http_req* req);

#endif
