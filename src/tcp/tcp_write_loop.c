#include "tcp_write_loop.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "logging/logging.h"
#include "tcp_server.h"
#include "tls.h"

static void complete_task(struct write_task* task, int err) {
    if (err != 0) {
        LOG_ERROR("Failed to complete write task for request %s %s from connection %s:%d error=%d (%s)",
                  req_method(task->req), req_path(task->req), req_remote_ipv4(task->req), req_remote_port(task->req),
                  err, errno_str(err));
    }
    if (task->cb != 0) {
        task->cb(task->data, err);
    }
    free(task);
}

static void pop_task(struct tcp_conn* conn, int err) {
    struct write_task* task = conn->wt_head;
    conn->wt_head = task->next;
    if (conn->wt_head == 0) {
        conn->wt_tail = 0;
    }
    task->next = 0;
    complete_task(task, err);
}

static void clear_task_list(struct tcp_conn* conn) {
    struct write_task* task;
    task = conn->wt_head;
    conn->wt_head = 0;
    conn->wt_tail = 0;
    while (task != 0) {
        struct write_task* next = task->next;
        complete_task(task, ECONNABORTED);
        task = next;
    }
}

enum write_worker_notification_type
{
    ww_notify_add,
    ww_notify_execute,
    ww_notify_remove,
};

struct write_worker_notification {
    enum write_worker_notification_type type;
    struct tcp_conn* conn;
    struct write_task* task;
};

void tcp_write_loop_add_conn(struct event_loop* w_loop, struct tcp_conn* conn) {
    tcp_conn_inc_refcount(conn);
    struct write_worker_notification notification;
    notification.conn = conn;
    notification.type = ww_notify_add;
    event_loop_send_notification(w_loop, &notification, sizeof(notification));
}

void tcp_write_loop_remove_conn(struct event_loop* w_loop, struct tcp_conn* conn) {
    struct write_worker_notification notification;
    notification.conn = conn;
    notification.type = ww_notify_remove;
    event_loop_send_notification(w_loop, &notification, sizeof(notification));
}

void tcp_write_loop_push(struct tcp_conn* conn, const char* buf, int buf_len, struct http_req* req, void* data,
                         write_task_cb cb) {
    struct write_task* task = malloc(sizeof(struct write_task));
    if (task == 0) {
        LOG_ERROR("Failed to allocate write task for connection %s:%d", ipv4_str(conn->ipv4), conn->port);
        cb(data, -1);
        close_tcp_conn(conn);
        return;
    }

    task->buf_crs = 0;
    task->buf_len = buf_len;
    task->buf = buf;
    task->req = req;
    task->data = data;
    task->cb = cb;

    tcp_conn_inc_refcount(conn);  // To make sure the connection stays alive until push_task is executed.

    struct write_worker_notification notification;
    notification.conn = conn;
    notification.task = task;
    notification.type = ww_notify_execute;
    event_loop_send_notification(&conn->server->w_loop, &notification, sizeof(notification));
}

static int push_task(struct tcp_conn* conn, struct write_task* task) {
    task->next = 0;
    if (conn->wt_tail != 0) {
        conn->wt_tail->next = task;
    }
    conn->wt_tail = task;
    if (conn->wt_head == 0) {
        conn->wt_head = task;
    }
    tcp_conn_dec_refcount(conn);
    return 0;
}

static void tcp_write_loop_process_writes(struct tcp_conn* conn) {
    struct write_task* task = conn->wt_head;
    while (task != 0) {
        ssize_t chunk_sz;
        if (conn->tls == 0) {
            chunk_sz = write(conn->fd, task->buf + task->buf_crs, task->buf_len - task->buf_crs);
            if (chunk_sz < 0 && errno != EWOULDBLOCK) {
                pop_task(conn, errno);
                close_tcp_conn(conn);
                break;
            }
        } else {
            chunk_sz = write_tls(conn->tls, task->buf + task->buf_crs, task->buf_len - task->buf_crs);
            if (chunk_sz < 0) {
                pop_task(conn, errno);
                close_tcp_conn(conn);
                break;
            }
        }
        if (chunk_sz > 0) {
            LOG_DEBUG("Wrote %d bytes to %s:%d", (int)chunk_sz, ipv4_str(conn->ipv4), conn->port);
            task->buf_crs += chunk_sz;
            if (task->buf_crs == task->buf_len) {
                pop_task(conn, 0);
                task = conn->wt_head;
            }
        }
    }
}

static int process_notification_cb(void* cb_data) {
    struct event_loop* w_loop = (struct event_loop*)cb_data;
    struct write_worker_notification notification;
    event_loop_recv_notification(w_loop, &notification, sizeof(notification));

    enum write_worker_notification_type type = notification.type;
    struct tcp_conn* conn = notification.conn;
    if (type == ww_notify_execute) {
        if (push_task(conn, notification.task) == 0) {
            tcp_write_loop_process_writes(conn);
        }
    } else if (type == ww_notify_remove) {
        clear_task_list(conn);
        if (event_loop_remove_write_fd(&conn->server->w_loop, conn->fd, conn) < 0) {
            LOG_ERROR("Failed to remove connection from TCP write loop: %s failed errno=%d (%s)",
                      event_loop_ctl_syscall_name, errno, errno_str(errno));
        }
        tcp_conn_dec_refcount(conn);
    } else if (type == ww_notify_add) {
        if (event_loop_add_write_fd(&conn->server->w_loop, conn->fd, conn) < 0) {
            LOG_ERROR("Failed to add connection to TCP write loop: %s failed errno=%d (%s)",
                      event_loop_ctl_syscall_name, errno, errno_str(errno));
            tcp_conn_dec_refcount(conn);
            return 0;
        }
        conn->wt_head = 0;
        conn->wt_tail = 0;
    }
    return 0;
}

static int process_event_cb(void* data, int flags, UNUSED void* cb_data) {
    if (flags & evf_write) {
        tcp_write_loop_process_writes((struct tcp_conn*)data);
    }
    return 0;
}

void run_write_loop(struct event_loop* w_loop) {
    int run_status = event_loop_run(w_loop, w_loop, process_event_cb, process_notification_cb);
    if (run_status != 0) {
        if (run_status < 0) {
            LOG_FATAL("TCP write loop failed: %s failed errno=%d (%s)", event_loop_run_syscall_name, errno,
                      errno_str(errno));
        } else {
            LOG_FATAL("TCP write loop failed: event processing callback returned error code=%d (%s)", run_status,
                      errno_str(run_status));
        }
    }
}
