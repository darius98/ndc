#ifndef NDC_HTTP_SERVER_HTTP_SERVER_H_
#define NDC_HTTP_SERVER_HTTP_SERVER_H_

#include "../conf/conf.h"
#include "../utils/ff_pthread.h"
#include "http_req.h"
#include "tcp_server.h"

struct http_handler {
    char* name;
    void* data;
    int (*should_handle)(void*, struct http_req*);
    void (*handle)(void*, struct http_req*);
};

struct http_server {
    struct tcp_server tcp_server;

    struct http_req* head;
    struct http_req* tail;

    pthread_mutex_t lock;
    pthread_cond_t cond_var;
    _Atomic(int) stopped;

    int req_buf_cap;

    int handlers_len;
    int handlers_cap;
    struct http_handler* handlers;

    int num_workers;
    pthread_t* workers;
};

/// Initialize a http server. Note: Aborts on failure.
void init_http_server(struct http_server* server, const struct conf* conf);

void install_http_handler(struct http_server* server, struct http_handler handler);

void start_http_server(struct http_server* server);

void http_response_write(struct http_req* req, const char* buf, int buf_len, void* cb_data, write_task_cb cb);

void http_response_end(struct http_req* req, int status, int error);

void http_response_fail(struct http_req* req);

#endif
