#ifndef NDC_TCP_CONN_TABLE_H_
#define NDC_TCP_CONN_TABLE_H_

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

struct tcp_conn_table* new_tcp_conn_table(int n_buckets, int bucket_init_cap, int conn_buf_len);

struct tcp_conn* tcp_conn_table_lookup(struct tcp_conn_table* table, int fd);

struct tcp_conn* new_tcp_conn(struct tcp_conn_table* table, int fd, int ipv4, int port);

void close_tcp_conn(struct http_req_queue* req_queue, struct tcp_conn_table* table, struct tcp_conn* conn);

void tcp_conn_inc_refcount(struct tcp_conn* conn);

void tcp_conn_dec_refcount(struct http_req_queue* req_queue, struct tcp_conn* conn);

#endif
