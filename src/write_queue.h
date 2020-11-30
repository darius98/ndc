#ifndef NDC_WRITE_SERVER_H_
#define NDC_WRITE_SERVER_H_

struct tcp_server;
struct tcp_conn;

struct write_task;

typedef void (*write_task_cb)(void* cb_data, struct tcp_conn* conn, int err);

struct write_queue;

struct write_queue* new_write_queue(struct tcp_server* tcp_server);

void write_queue_push(struct write_queue* queue, struct tcp_conn* conn, const char* buf, int buf_len, void* cb_data,
                      write_task_cb cb);

#endif
