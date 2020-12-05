#ifndef NDC_TCP_SERVER_H_
#define NDC_TCP_SERVER_H_

#include "conf.h"
#include "write_queue.h"

struct tcp_conn {
    _Atomic(int) ref_count;
    int fd;
    int buf_len;
    int buf_cap;
    char* buf;
    void* user_data;
    int ipv4;
    int port;
    _Atomic(int) is_closed;
};

struct tcp_conn_table_bucket {
    int size;
    int capacity;
    struct tcp_conn** entries;
};

struct tcp_conn_table {
    int size;
    int n_buckets;
    struct tcp_conn_table_bucket* buckets;
};

struct tcp_server {
    struct tcp_conn_table conn_table;
    struct write_queue w_queue;
    struct tcp_server_conf* conf;
    int listen_fd;
    int notify_pipe[2];
    int port;
    void* cb_data;
};

/// Initialize a TCP server. Note: Aborts on failure.
void init_tcp_server(struct tcp_server* server, int port, struct tcp_server_conf* conf,
                     struct tcp_write_queue_conf* w_queue_conf);

struct tcp_conn* find_tcp_conn(struct tcp_server* server, int fd);

struct tcp_conn* accept_tcp_conn(struct tcp_server* server);

int recv_from_tcp_conn(struct tcp_server* server, struct tcp_conn* conn);

void tcp_conn_inc_refcount(struct tcp_conn* conn);

void tcp_conn_dec_refcount(struct tcp_conn* conn);

void close_tcp_conn(struct tcp_server* server, struct tcp_conn* conn);

void tcp_server_process_notification(struct tcp_server* server);

void run_tcp_server_loop(struct tcp_server* server);

// These callbacks are not implemented in the TCP server.

int tcp_conn_after_open_callback(void* cb_data, struct tcp_conn* conn);

int tcp_conn_on_recv_callback(void* cb_data, struct tcp_conn* conn);

void tcp_conn_before_close_callback(void* cb_data, struct tcp_conn* conn);

#endif
