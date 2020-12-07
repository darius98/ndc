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

struct write_task_list {
    _Atomic(int) ref_count;
    struct tcp_conn* conn;
    struct write_task* head;
    struct write_task* tail;
};

struct write_task_list_table_bucket {
    pthread_mutex_t lock;
    pthread_mutex_t task_list_lock;
    int len;
    int cap;
    struct write_task_list** entries;
};

struct write_task_list_table {
    _Atomic(int) size;
    int n_buckets;
    struct write_task_list_table_bucket* buckets;
};

struct write_queue {
    struct tcp_server* tcp_server;
    struct write_task_list_table task_lists;
    int loop_notify_pipe[2];
    int loop_fd;
    int loop_max_events;
    pthread_t worker;
};

void init_write_queue(struct write_queue* queue, struct tcp_write_queue_conf* conf, struct tcp_server* tcp_server);

int write_queue_add_conn(struct write_queue* queue, struct tcp_conn* conn);

void write_queue_remove_conn(struct write_queue* queue, struct tcp_conn* conn);

void write_queue_push(struct write_queue* queue, struct tcp_conn* conn, const char* buf, int buf_len, void* cb_data,
                      write_task_cb cb);

void write_queue_process_writes(struct write_queue* queue, int fd);

void write_queue_process_notification(struct write_queue* queue);

/// Initialize a new write_worker_loop. Note: Aborts on failure.
void init_write_loop(struct write_queue* queue);

void run_write_loop(struct write_queue* queue);

int write_loop_add_fd(struct write_queue* queue, int fd);

#endif
