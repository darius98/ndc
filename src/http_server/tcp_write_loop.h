#ifndef NDC_HTTP_SERVER_TCP_WRITE_LOOP_H_
#define NDC_HTTP_SERVER_TCP_WRITE_LOOP_H_

#include "conf/conf.h"
#include "http_req.h"
#include "utils/config.h"
#include "utils/ff_pthread.h"

NDC_BEGIN_DECLS

struct tcp_server;
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

struct tcp_write_loop {
    int loop_notify_pipe[2];
    int loop_fd;
    int loop_max_events;
    pthread_t worker;
};

void init_tcp_write_loop(struct tcp_write_loop* w_loop, const struct tcp_write_loop_conf* conf);

void tcp_write_loop_add_conn(struct tcp_write_loop* w_loop, struct tcp_conn* conn);

void tcp_write_loop_remove_conn(struct tcp_write_loop* w_loop, struct tcp_conn* conn);

/// Note: It is the responsibility of the callback to log an appropriate message for errors.
void tcp_write_loop_push(struct tcp_conn* conn, const char* buf, int buf_len, struct http_req* req, void* data,
                         write_task_cb cb);

void tcp_write_loop_process_writes(struct tcp_conn* conn);

void tcp_write_loop_process_notification(struct tcp_write_loop* w_loop);

/// Initialize a new write_worker_loop. Note: Aborts on failure.
void init_write_loop(struct tcp_write_loop* w_loop);

void run_write_loop(struct tcp_write_loop* w_loop);

int write_loop_add_conn(struct tcp_conn* conn);

void write_loop_remove_conn(struct tcp_conn* conn);

NDC_END_DECLS

#endif
