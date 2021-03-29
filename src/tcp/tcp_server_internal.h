#ifndef NDC_TCP_TCP_SERVER_INTERNAL_H_
#define NDC_TCP_TCP_SERVER_INTERNAL_H_

#include "tcp_conn.h"
#include "utils/config.h"

NDC_BEGIN_DECLS

struct tcp_write_task {
    int buf_crs;
    int buf_len;
    const char* buf;
    void* data;
    tcp_conn_write_cb cb;
    struct tcp_write_task* next;
};

enum tcp_write_loop_notification_type
{
    ww_notify_add,
    ww_notify_execute,
    ww_notify_remove,
};

struct tcp_write_loop_notification {
    enum tcp_write_loop_notification_type type;
    struct tcp_conn* conn;
    struct tcp_write_task* task;
};

enum tcp_read_loop_notification_type
{ ts_notify_close_conn, };

struct tcp_read_loop_notification {
    enum tcp_read_loop_notification_type type;
    struct tcp_conn* conn;
};

NDC_END_DECLS

#endif
