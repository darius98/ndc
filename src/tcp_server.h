#ifndef NDC_TCP_SERVER_H_
#define NDC_TCP_SERVER_H_

#include <netinet/in.h>
#include <stdatomic.h>

struct tcp_conn {
    atomic_int ref_count;
    int fd;
    int buf_len;
    int buf_cap;
    char* buf;
    void* user_data;
    int ipv4;
    int port;
};

struct tcp_conn_table;

struct tcp_server {
    struct tcp_conn_table* conn_table;
    int listen_fd;
    int port;

    int conn_buf_len;

    void* user_data;
};

struct tcp_server* init_tcp_server(int port, int max_clients, int n_buckets, int bucket_init_cap, int conn_buf_len,
                                   void* user_data);

struct tcp_conn* find_tcp_conn(struct tcp_server* server, int fd);

struct tcp_conn* accept_tcp_conn(struct tcp_server* server);

int recv_from_tcp_conn(struct tcp_server* server, struct tcp_conn* conn);

void tcp_conn_inc_refcount(struct tcp_conn* conn);

void tcp_conn_dec_refcount(struct tcp_conn* conn);

void close_tcp_conn(struct tcp_server* server, struct tcp_conn* conn);

void run_tcp_server_loop(struct tcp_server* server);

// These callbacks are not implemented in the TCP server.

int tcp_conn_after_open_callback(void* user_data, struct tcp_conn* conn);

int tcp_conn_on_recv_callback(void* user_data, struct tcp_conn* conn);

int tcp_conn_before_close_callback(void* user_data, struct tcp_conn* conn);

#endif
