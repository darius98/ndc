#ifndef NDC_HTTP_SERVER_TCP_WRITE_LOOP_H_
#define NDC_HTTP_SERVER_TCP_WRITE_LOOP_H_

#include "conf/conf.h"
#include "event_loop/event_loop.h"
#include "http/server/http_req.h"
#include "utils/config.h"
#include "utils/ff_pthread.h"

NDC_BEGIN_DECLS

struct tcp_conn;

struct write_task {
    int buf_crs;
    int buf_len;
    const char* buf;
    struct http_req* req;
    void* data;
    write_task_cb cb;
    struct write_task* next;
};

void tcp_write_loop_add_conn(struct event_loop* w_loop, struct tcp_conn* conn);

void tcp_write_loop_remove_conn(struct event_loop* w_loop, struct tcp_conn* conn);

/// Note: It is the responsibility of the callback to log an appropriate message for errors.
void tcp_write_loop_push(struct tcp_conn* conn, const char* buf, int buf_len, struct http_req* req, void* data,
                         write_task_cb cb);

void run_write_loop(struct event_loop* w_loop);

NDC_END_DECLS

#endif
