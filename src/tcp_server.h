#ifndef NDC_TCP_SERVER_H_
#define NDC_TCP_SERVER_H_

#include "conf.h"
#include "write_queue.h"

struct tcp_conn {
    _Atomic(int) ref_count;
    _Atomic(int) is_closed;
    int fd;
    void* tls;
    void* user_data;
    int ipv4;
    int port;
    char buf[];
};

struct tcp_server {
    struct write_queue w_queue;
    const struct tcp_server_conf* conf;
    int listen_fd;
    int loop_fd;
    int notify_pipe[2];
    int port;
    void* tls_ctx;
    void* cb_data;
};

/// Initialize a TCP server. Note: Aborts on failure.
void init_tcp_server(struct tcp_server* server, int port, const struct tcp_server_conf* conf,
                     const struct tcp_write_queue_conf* w_queue_conf);

struct tcp_conn* accept_tcp_conn(struct tcp_server* server);

void recv_from_tcp_conn(struct tcp_server* server, struct tcp_conn* conn);

void tcp_conn_inc_refcount(struct tcp_conn* conn);

void tcp_conn_dec_refcount(struct tcp_conn* conn);

void close_tcp_conn_in_loop(struct tcp_server* server, struct tcp_conn* conn);

void close_tcp_conn(struct tcp_server* server, struct tcp_conn* conn);

void tcp_server_process_notification(struct tcp_server* server);

void run_tcp_server_loop(struct tcp_server* server);

void remove_conn_from_read_loop(struct tcp_server* server, struct tcp_conn* conn);

// These callbacks are not implemented in the TCP server.

int tcp_conn_after_open_callback(void* cb_data, struct tcp_conn* conn);

int tcp_conn_on_recv_callback(void* cb_data, struct tcp_conn* conn, int num_bytes);

void tcp_conn_before_close_callback(void* cb_data, struct tcp_conn* conn);

#endif
