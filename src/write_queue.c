#include "write_queue.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fd.h"
#include "logging.h"
#include "tcp_server.h"
#include "tls.h"

static void pop_task(struct tcp_conn* conn, int err) {
    struct write_task* task = conn->wt_head;
    conn->wt_head = task->next;
    if (conn->wt_head == 0) {
        conn->wt_tail = 0;
    }
    task->next = 0;
    task->cb(task->cb_data, conn, err);
    free(task);
}

static void clear_task_list(struct tcp_conn* conn) {
    struct write_task* task;
    task = conn->wt_head;
    conn->wt_head = 0;
    conn->wt_tail = 0;
    while (task != 0) {
        struct write_task* next = task->next;
        task->cb(task->cb_data, conn, ECONNABORTED);
        free(task);
        task = next;
    }
}

static void add_tcp_conn(struct write_queue* queue, struct tcp_conn* conn) {
    if (write_loop_add_conn(queue, conn) < 0) {
        tcp_conn_dec_refcount(conn);
        return;
    }
    conn->wt_head = 0;
    conn->wt_tail = 0;
}

static void remove_tcp_conn(struct write_queue* queue, struct tcp_conn* conn) {
    clear_task_list(conn);
    write_loop_remove_conn(queue, conn);
    tcp_conn_dec_refcount(conn);
}

static void* write_queue_worker(void* arg) {
    struct write_queue* queue = (struct write_queue*)arg;
    run_write_loop(queue);
    return 0;
}

void init_write_queue(struct write_queue* queue, const struct tcp_write_queue_conf* conf,
                      struct tcp_server* tcp_server) {
    queue->tcp_server = tcp_server;
    queue->loop_max_events = conf->events_batch_size;
    if (make_nonblocking_pipe(queue->loop_notify_pipe) < 0) {
        LOG_FATAL("Failed to create notify pipe for TCP write queue");
    }
    init_write_loop(queue);
    ff_pthread_create(&queue->worker, 0, write_queue_worker, queue);
}

struct write_worker_notification {
    enum
    {
        ww_notify_add,
        ww_notify_execute,
        ww_notify_remove
    } type;
    struct tcp_conn* conn;
    struct write_task* task;
};

static void write_notification(struct write_queue* queue, struct write_worker_notification notification) {
    int ret = write(queue->loop_notify_pipe[1], &notification, sizeof(struct write_worker_notification));
    if (ret != sizeof(struct write_worker_notification)) {
        if (ret < 0) {
            LOG_FATAL("Failed to write() to TCP server notify pipe errno=%d (%s)", errno, errno_str(errno));
        } else {
            LOG_FATAL("Failed to write() to TCP server notify pipe, wrote %d out of %d bytes.", ret,
                      (int)sizeof(struct write_worker_notification));
        }
    }
}

void write_queue_add_conn(struct write_queue* queue, struct tcp_conn* conn) {
    tcp_conn_inc_refcount(conn);
    struct write_worker_notification notification;
    notification.conn = conn;
    notification.type = ww_notify_add;
    write_notification(queue, notification);
}

void write_queue_remove_conn(struct write_queue* queue, struct tcp_conn* conn) {
    struct write_worker_notification notification;
    notification.conn = conn;
    notification.type = ww_notify_remove;
    write_notification(queue, notification);
}

void write_queue_push(struct write_queue* queue, struct tcp_conn* conn, const char* buf, int buf_len, void* cb_data,
                      write_task_cb cb) {
    struct write_task* task = malloc(sizeof(struct write_task));
    if (task == 0) {
        LOG_ERROR("Failed to allocate write task for connection %s:%d", ipv4_str(conn->ipv4), conn->port);
        cb(cb_data, conn, -1);
        close_tcp_conn(queue->tcp_server, conn);
        return;
    }

    task->buf_crs = 0;
    task->buf_len = buf_len;
    task->buf = buf;
    task->cb_data = cb_data;
    task->cb = cb;

    struct write_worker_notification notification;
    notification.conn = conn;
    notification.task = task;
    notification.type = ww_notify_execute;
    write_notification(queue, notification);
    tcp_conn_inc_refcount(conn);  // To make sure the connection stays alive until push_task is executed.
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

void write_queue_process_writes(struct write_queue* queue, struct tcp_conn* conn) {
    struct write_task* task = conn->wt_head;
    while (task != 0) {
        ssize_t chunk_sz;
        if (conn->tls == 0) {
            chunk_sz = write(conn->fd, task->buf + task->buf_crs, task->buf_len - task->buf_crs);
            if (chunk_sz < 0 && errno != EWOULDBLOCK) {
                pop_task(conn, errno);
                close_tcp_conn(queue->tcp_server, conn);
                break;
            }
        } else {
            chunk_sz = write_tls(conn->tls, task->buf + task->buf_crs, task->buf_len - task->buf_crs);
            if (chunk_sz < 0) {
                pop_task(conn, errno);
                close_tcp_conn(queue->tcp_server, conn);
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

void write_queue_process_notification(struct write_queue* queue) {
    struct write_worker_notification notification;
    errno = 0;
    ssize_t n_bytes = read(queue->loop_notify_pipe[0], &notification, sizeof(struct write_worker_notification));
    if (n_bytes != sizeof(struct write_worker_notification)) {
        LOG_FATAL("Write worker loop: failed to read notification from pipe, returned %d, errno=%d (%s)", (int)n_bytes,
                  errno, errno_str(errno));
    }
    if (notification.type == ww_notify_execute) {
        if (push_task(notification.conn, notification.task) == 0) {
            write_queue_process_writes(queue, notification.conn);
        }
    } else if (notification.type == ww_notify_remove) {
        remove_tcp_conn(queue, notification.conn);
    } else if (notification.type == ww_notify_add) {
        add_tcp_conn(queue, notification.conn);
    }
}
