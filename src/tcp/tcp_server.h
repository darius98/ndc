#ifndef NDC_TCP_TCP_SERVER_H_
#define NDC_TCP_TCP_SERVER_H_

#include <stdint.h>

#include "conf/conf.h"
#include "event_loop/event_loop.h"
#include "tcp_conn.h"
#include "utils/config.h"
#include "utils/ff_pthread.h"

NDC_BEGIN_DECLS

struct tcp_server;

typedef int (*tcp_server_recv_cb)(void*, struct tcp_conn*, int);
typedef void (*tcp_server_conn_closed_cb)(void*, struct tcp_conn*);

struct tcp_server {
    struct event_loop r_loop;
    struct event_loop w_loop;
    pthread_t w_loop_thread;
    const struct tcp_server_conf* conf;
    int listen_fd;
    int port;
    void* tls_ctx;
    void* data;
    tcp_server_recv_cb on_conn_recv;
    tcp_server_conn_closed_cb on_conn_closed;
};

/// Initialize a TCP server. Note: Aborts on failure.
void tcp_server_init(struct tcp_server* server, int port, const struct tcp_server_conf* conf,
                     const struct tcp_write_loop_conf* w_loop_conf, void* data, tcp_server_recv_cb on_conn_recv,
                     tcp_server_conn_closed_cb on_conn_closed);

void tcp_server_run(struct tcp_server* server);

NDC_END_DECLS

#endif
