#ifndef NDC_HTTP_SERVER_HTTP_SERVER_H_
#define NDC_HTTP_SERVER_HTTP_SERVER_H_

#include "access_log.h"
#include "conf/conf.h"
#include "http_req.h"
#include "tcp/tcp_server.h"
#include "utils/config.h"
#include "utils/ff_pthread.h"

NDC_BEGIN_DECLS

struct http_handler {
    char* name;
    void* data;
    int (*should_handle)(void*, struct http_req*);
    void (*handle)(void*, struct http_req*);
};

struct http_server {
    struct tcp_server tcp_server;
    struct access_log access_log;

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

NDC_END_DECLS

#endif
