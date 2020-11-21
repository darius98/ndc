#ifndef NDC_TCP_CONN_TABLE_H_
#define NDC_TCP_CONN_TABLE_H_

#include <netinet/in.h>

#include "http.h"

struct tcp_conn {
    int fd;
    int buf_len;
    int buf_cap;
    char* buf;
    struct http_req* cur_req;
    char ip[INET_ADDRSTRLEN];
    int port;
};

struct tcp_conn_table;

struct tcp_conn_table* new_tcp_conn_table(int n_buckets, int bucket_init_cap, int conn_buf_len);

struct tcp_conn* tcp_conn_table_lookup(struct tcp_conn_table* table, int fd);

struct tcp_conn* new_tcp_conn(struct tcp_conn_table* table, int fd, char* ip, int port);

int delete_tcp_conn(struct tcp_conn_table* table, struct tcp_conn* connection);

#endif
