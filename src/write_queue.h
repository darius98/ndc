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

struct tcp_conn_table_bucket {
    int len;
    int cap;
    struct tcp_conn** entries;
};

struct tcp_conn_table {
    _Atomic(int) size;
    int n_buckets;
    struct tcp_conn_table_bucket* buckets;
};

struct write_queue {
    struct tcp_server* tcp_server;
    struct tcp_conn_table table;
    int loop_notify_pipe[2];
    int loop_fd;
    int loop_max_events;
    pthread_t worker;
};

void init_write_queue(struct write_queue* queue, const struct tcp_write_queue_conf* conf,
                      struct tcp_server* tcp_server);

void write_queue_add_conn(struct write_queue* queue, struct tcp_conn* conn);

void write_queue_remove_conn(struct write_queue* queue, struct tcp_conn* conn);

/// Note: It is the responsibility of the callback to log an appropriate message for errors.
void write_queue_push(struct write_queue* queue, struct tcp_conn* conn, const char* buf, int buf_len, void* cb_data,
                      write_task_cb cb);

void write_queue_process_writes(struct write_queue* queue, int fd);

void write_queue_process_notification(struct write_queue* queue);

/// Initialize a new write_worker_loop. Note: Aborts on failure.
void init_write_loop(struct write_queue* queue);

void run_write_loop(struct write_queue* queue);

int write_loop_add_fd(struct write_queue* queue, int fd);

void write_loop_remove_fd(struct write_queue* queue, int fd);

#endif
