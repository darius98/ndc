#ifndef NDC_WRITE_SERVER_H_
#define NDC_WRITE_SERVER_H_

#include "conf.h"
#include "ff_pthread.h"

struct tcp_server;
struct tcp_conn;

typedef void (*write_task_cb)(void* cb_data, struct tcp_conn* conn, int err);

struct write_task {
    int buf_crs;
    int buf_len;
    const char* buf;
    void* cb_data;
    write_task_cb cb;
    struct write_task* next;
};

struct tcp_write_loop {
    struct tcp_server* tcp_server;
    int loop_notify_pipe[2];
    int loop_fd;
    int loop_max_events;
    pthread_t worker;
};

void init_tcp_write_loop(struct tcp_write_loop* w_loop, const struct tcp_write_loop_conf* conf,
                         struct tcp_server* tcp_server);

void tcp_write_loop_add_conn(struct tcp_write_loop* w_loop, struct tcp_conn* conn);

void tcp_write_loop_remove_conn(struct tcp_write_loop* w_loop, struct tcp_conn* conn);

/// Note: It is the responsibility of the callback to log an appropriate message for errors.
void tcp_write_loop_push(struct tcp_write_loop* w_loop, struct tcp_conn* conn, const char* buf, int buf_len,
                         void* cb_data, write_task_cb cb);

void tcp_write_loop_process_writes(struct tcp_write_loop* w_loop, struct tcp_conn* conn);

void tcp_write_loop_process_notification(struct tcp_write_loop* w_loop);

/// Initialize a new write_worker_loop. Note: Aborts on failure.
void init_write_loop(struct tcp_write_loop* w_loop);

void run_write_loop(struct tcp_write_loop* w_loop);

int write_loop_add_conn(struct tcp_write_loop* w_loop, struct tcp_conn* conn);

void write_loop_remove_conn(struct tcp_write_loop* w_loop, struct tcp_conn* conn);

#endif
