#ifndef NDC_TCP_SERVER_H_
#define NDC_TCP_SERVER_H_

#include <netinet/in.h>
#include <stdatomic.h>

#include "http.h"

struct tcp_conn {
    atomic_int ref_count;
    int fd;
    int buf_len;
    int buf_cap;
    char* buf;
    struct http_req* cur_req;
    int ipv4;
    int port;
};

struct tcp_conn_table;

struct tcp_server {
    struct tcp_conn_table* conn_table;
    struct http_req_queue* req_queue;
    int listen_fd;
    int port;

    int conn_buf_len;
};

struct tcp_server* init_tcp_server(struct http_req_queue* req_queue, int port, int max_clients, int n_buckets,
                                   int bucket_init_cap, int conn_buf_len);

struct tcp_conn* find_tcp_conn(struct tcp_server* server, int fd);

struct tcp_conn* accept_tcp_conn(struct tcp_server* server);

void recv_from_tcp_conn(struct tcp_server* server, struct tcp_conn* conn);

void tcp_conn_inc_refcount(struct tcp_conn* conn);

void tcp_conn_dec_refcount(struct tcp_conn* conn);

void close_tcp_conn(struct tcp_server* server, struct tcp_conn* conn);

void run_tcp_server_loop(struct tcp_server *server);

#endif
