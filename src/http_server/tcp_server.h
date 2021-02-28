#ifndef NDC_TCP_SERVER_H_
#define NDC_TCP_SERVER_H_

#include "../conf/conf.h"
#include "tcp_write_loop.h"

struct tcp_conn {
    _Atomic(int) ref_count;
    _Atomic(int) is_closed;
    int fd;
    void* tls;
    struct write_task* wt_head;
    struct write_task* wt_tail;
    void* user_data;
    int ipv4;
    int port;
    char buf[];
};

typedef int(*on_conn_open_cb)(void*, struct tcp_conn*);
typedef int(*on_conn_recv_cb)(void*, struct tcp_conn*, int);
typedef void(*on_conn_closed_cb)(void*, struct tcp_conn*);

struct tcp_server {
    struct tcp_write_loop w_loop;
    const struct tcp_server_conf* conf;
    int listen_fd;
    int loop_fd;
    int notify_pipe[2];
    int port;
    void* tls_ctx;
    void* cb_data;
    on_conn_open_cb on_conn_open;
    on_conn_recv_cb on_conn_recv;
    on_conn_closed_cb on_conn_closed;
};

/// Initialize a TCP server. Note: Aborts on failure.
void init_tcp_server(struct tcp_server* server, int port, const struct tcp_server_conf* conf,
                     const struct tcp_write_loop_conf* w_loop_conf, void* cb_data, on_conn_open_cb on_conn_open,
                     on_conn_recv_cb on_conn_recv, on_conn_closed_cb on_conn_closed);

struct tcp_conn* accept_tcp_conn(struct tcp_server* server);

void recv_from_tcp_conn(struct tcp_server* server, struct tcp_conn* conn);

void tcp_conn_inc_refcount(struct tcp_conn* conn);

void tcp_conn_dec_refcount(struct tcp_conn* conn);

void close_tcp_conn_in_loop(struct tcp_server* server, struct tcp_conn* conn);

void close_tcp_conn(struct tcp_server* server, struct tcp_conn* conn);

void tcp_server_process_notification(struct tcp_server* server);

void run_tcp_server_loop(struct tcp_server* server);

void remove_conn_from_read_loop(struct tcp_server* server, struct tcp_conn* conn);

#endif
