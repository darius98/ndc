#ifndef NDC_HTTP_SERVER_TCP_SERVER_H_
#define NDC_HTTP_SERVER_TCP_SERVER_H_

#include <stdint.h>

#include "conf/conf.h"
#include "event_loop/event_loop.h"
#include "tcp_write_loop.h"
#include "utils/config.h"

NDC_BEGIN_DECLS

struct tcp_server;

struct tcp_conn {
    _Atomic(int) ref_count;
    _Atomic(int) is_closed;
    struct tcp_server* server;
    int fd;
    void* tls;
    struct write_task* wt_head;
    struct write_task* wt_tail;
    void* user_data;
    uint32_t ipv4;
    int port;
    char buf[];
};

typedef int (*on_conn_recv_cb)(void*, struct tcp_conn*, int);
typedef void (*on_conn_closed_cb)(void*, struct tcp_conn*);

struct tcp_server {
    struct event_loop r_loop;
    struct event_loop w_loop;
    pthread_t w_loop_thread;
    const struct tcp_server_conf* conf;
    int listen_fd;
    int port;
    void* tls_ctx;
    void* data;
    on_conn_recv_cb on_conn_recv;
    on_conn_closed_cb on_conn_closed;
};

/// Initialize a TCP server. Note: Aborts on failure.
void init_tcp_server(struct tcp_server* server, int port, const struct tcp_server_conf* conf,
                     const struct tcp_write_loop_conf* w_loop_conf, void* data, on_conn_recv_cb on_conn_recv,
                     on_conn_closed_cb on_conn_closed);

void run_tcp_server_loop(struct tcp_server* server);

void tcp_conn_inc_refcount(struct tcp_conn* conn);

void tcp_conn_dec_refcount(struct tcp_conn* conn);

void close_tcp_conn(struct tcp_conn* conn);

NDC_END_DECLS

#endif
