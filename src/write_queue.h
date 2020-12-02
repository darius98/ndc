#ifndef NDC_WRITE_SERVER_H_
#define NDC_WRITE_SERVER_H_

struct tcp_server;
struct tcp_conn;

struct write_task;

typedef void (*write_task_cb)(void* cb_data, struct tcp_conn* conn, int err);

struct write_task_list;
struct write_queue;

struct write_queue* new_write_queue(struct tcp_server* tcp_server, int task_lists_n_buckets,
                                    int task_lists_bucket_init_cap);

int write_queue_add_conn(struct write_queue* queue, struct tcp_conn* conn);

void write_queue_remove_conn(struct write_queue* queue, struct tcp_conn* conn);

void write_queue_push(struct write_queue* queue, struct tcp_conn* conn, const char* buf, int buf_len, void* cb_data,
                      write_task_cb cb);

void write_queue_process_writes(struct write_queue* queue, int fd);

void write_queue_process_notification(struct write_queue* queue);

#endif
