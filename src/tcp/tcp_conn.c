#include "tcp_conn.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <unistd.h>

#include "logging/logging.h"
#include "tcp_server.h"
#include "tcp_server_internal.h"
#include "tls.h"

void tcp_conn_write(struct tcp_conn* conn, const char* buf, int buf_len, void* data, tcp_conn_write_cb cb) {
    struct tcp_write_task* task = malloc(sizeof(struct tcp_write_task));
    if (task == 0) {
        LOG_ERROR("Failed to allocate write task for connection %s:%d", ipv4_str(conn->ipv4), conn->port);
        cb(data, -1);
        tcp_conn_close(conn);
        return;
    }

    task->buf_crs = 0;
    task->buf_len = buf_len;
    task->buf = buf;
    task->data = data;
    task->cb = cb;

    tcp_conn_inc_refcount(conn);  // To make sure the connection stays alive until push_task is executed.

    struct tcp_write_loop_notification notification;
    notification.conn = conn;
    notification.task = task;
    notification.type = ww_notify_execute;
    event_loop_send_notification(&conn->server->w_loop, &notification, sizeof(notification));
}

void tcp_conn_inc_refcount(struct tcp_conn* conn) {
    atomic_fetch_add_explicit(&conn->ref_count, 1, memory_order_release);
}

void tcp_conn_dec_refcount(struct tcp_conn* conn) {
    int ref_cnt = atomic_fetch_sub_explicit(&conn->ref_count, 1, memory_order_acq_rel);
    if (ref_cnt == 1) {
        LOG_DEBUG("Reclaiming memory and file descriptor for tcp connection %s:%d (fd=%d)", ipv4_str(conn->ipv4),
                  conn->port, conn->fd);
        free_tls(conn->tls);
        if (close(conn->fd) < 0) {
            LOG_ERROR("Failed to close file descriptor %d for connection %s:%d, errno=%d (%s)", conn->fd,
                      ipv4_str(conn->ipv4), conn->port, errno, errno_str(errno));
        }
        free(conn);
    }
}

void tcp_conn_close(struct tcp_conn* conn) {
    if (atomic_exchange_explicit(&conn->is_closed, 1, memory_order_acq_rel) == 1) {
        LOG_DEBUG("Trying to close TCP connection that is already closed %s:%d (fd=%d)", ipv4_str(conn->ipv4),
                  conn->port, conn->fd);
        return;
    }

    struct tcp_read_loop_notification notification;
    notification.type = ts_notify_close_conn;
    notification.conn = conn;
    event_loop_send_notification(&conn->server->r_loop, &notification, sizeof(notification));
}
