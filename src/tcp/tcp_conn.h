#ifndef NDC_TCP_TCP_CONN_H_
#define NDC_TCP_TCP_CONN_H_

#include <stdint.h>

#include "utils/config.h"

NDC_BEGIN_DECLS

struct tcp_conn {
    _Atomic(int) ref_count;
    _Atomic(int) is_closed;
    struct tcp_server* server;
    int fd;
    void* tls;
    struct tcp_write_task* wt_head;
    struct tcp_write_task* wt_tail;
    void* user_data;
    uint32_t ipv4;
    int port;
    char buf[];
};

typedef void (*tcp_conn_write_cb)(void*, int);

void tcp_conn_write(struct tcp_conn* conn, const char* buf, int buf_len, void* data, tcp_conn_write_cb cb);

void tcp_conn_inc_refcount(struct tcp_conn* conn);

void tcp_conn_dec_refcount(struct tcp_conn* conn);

void tcp_conn_close(struct tcp_conn* conn);

NDC_END_DECLS

#endif
