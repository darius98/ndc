#include "tcp_server.h"

#include <errno.h>
#include <netinet/in.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "logging/logging.h"
#include "tls.h"
#include "utils/fd.h"

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

struct write_task {
    int buf_crs;
    int buf_len;
    const char* buf;
    struct http_req* req;
    void* data;
    write_task_cb cb;
    struct write_task* next;
};

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

static int w_loop_process_notification_cb(void* cb_data) {
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

static int w_loop_process_event_cb(void* data, int flags, UNUSED void* cb_data) {
    if (flags & evf_write) {
        tcp_write_loop_process_writes((struct tcp_conn*)data);
    }
    return 0;
}

static void* run_write_loop_in_thread(void* arg) {
    struct event_loop* w_loop = (struct event_loop*)arg;
    int run_status = event_loop_run(w_loop, w_loop, w_loop_process_event_cb, w_loop_process_notification_cb);
    if (run_status != 0) {
        if (run_status < 0) {
            LOG_FATAL("TCP write loop failed: %s failed errno=%d (%s)", event_loop_run_syscall_name, errno,
                      errno_str(errno));
        } else {
            LOG_FATAL("TCP write loop failed: event processing callback returned error code=%d (%s)", run_status,
                      errno_str(run_status));
        }
    }
    return 0;
}

static int listen_tcp(int port, int backlog) {
    int fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        LOG_ERROR("socket() failed errno=%d (%s)", errno, errno_str(errno));
        return -1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(struct sockaddr_in));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(port);
    if (bind(fd, (const struct sockaddr*)&server_addr, sizeof(struct sockaddr_in)) < 0) {
        LOG_ERROR("bind() failed errno=%d (%s)", errno, errno_str(errno));
        return -1;
    }

    if (listen(fd, backlog) < 0) {
        LOG_ERROR("listen() failed errno=%d (%s)", errno, errno_str(errno));
        return -1;
    }

    return fd;
}

void init_tcp_server(struct tcp_server* server, int port, const struct tcp_server_conf* conf,
                     const struct tcp_write_loop_conf* w_loop_conf, void* data, on_conn_recv_cb on_conn_recv,
                     on_conn_closed_cb on_conn_closed) {
    event_loop_init(&server->r_loop, conf->events_batch_size);
    event_loop_init(&server->w_loop, w_loop_conf->events_batch_size);
    ff_pthread_create(&server->w_loop_thread, 0, run_write_loop_in_thread, &server->w_loop);
    server->tls_ctx = init_tls(conf->tls_cert_pem);
    server->conf = conf;
    server->port = port;
    server->data = data;
    server->on_conn_recv = on_conn_recv;
    server->on_conn_closed = on_conn_closed;

    server->listen_fd = listen_tcp(port, conf->backlog);
    if (server->listen_fd < 0) {
        LOG_FATAL("Failed to initialize TCP server");
    }
    if (event_loop_add_read_fd(&server->r_loop, server->listen_fd, &server->listen_fd) < 0) {
        LOG_FATAL("Failed to initialize TCP server: %s failed errno=%d (%s)", event_loop_ctl_syscall_name, errno,
                  errno_str(errno));
    }
}

static void close_and_log(int fd, uint32_t ipv4, int port) {
    if (close(fd) < 0) {
        LOG_ERROR("Failed to close file descriptor %d for connection %s:%d, errno=%d (%s)", fd, ipv4_str(ipv4), port,
                  errno, errno_str(errno));
    }
}

static void tcp_write_loop_add_conn(struct event_loop* w_loop, struct tcp_conn* conn) {
    tcp_conn_inc_refcount(conn);
    struct write_worker_notification notification;
    notification.conn = conn;
    notification.type = ww_notify_add;
    event_loop_send_notification(w_loop, &notification, sizeof(notification));
}

static void tcp_write_loop_remove_conn(struct event_loop* w_loop, struct tcp_conn* conn) {
    struct write_worker_notification notification;
    notification.conn = conn;
    notification.type = ww_notify_remove;
    event_loop_send_notification(w_loop, &notification, sizeof(notification));
}

static void close_tcp_conn_in_loop(struct tcp_conn* conn) {
    conn->server->on_conn_closed(conn->server->data, conn);
    if (event_loop_remove_read_fd(&conn->server->r_loop, conn->fd, conn) < 0) {
        LOG_ERROR("Could not remove TCP connection %s:%d (fd=%d) from read loop, %s failed errno=%d (%s)",
                  ipv4_str(conn->ipv4), conn->port, conn->fd, event_loop_ctl_syscall_name, errno, errno_str(errno));
    }
    tcp_write_loop_remove_conn(&conn->server->w_loop, conn);
    LOG_DEBUG("TCP client disconnected: %s:%d (fd=%d)", ipv4_str(conn->ipv4), conn->port, conn->fd);
    tcp_conn_dec_refcount(conn);
}

static int tcp_conn_buf_cap(struct tcp_server* server) {
    return (int)(server->conf->connection_buffer_size - sizeof(struct tcp_conn) - 1);
}

static void accept_tcp_conn(struct tcp_server* server) {
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(struct sockaddr_in);
    int fd = accept(server->listen_fd, (struct sockaddr*)&client_addr, &client_addr_len);
    if (fd < 0) {
        LOG_ERROR("Failed to accept new TCP connection: accept() failed errno=%d (%s)", errno, errno_str(errno));
        return;
    }

    uint32_t ipv4 = client_addr.sin_addr.s_addr;
    int port = client_addr.sin_port;

    if (set_nonblocking(fd) < 0) {
        LOG_ERROR("Failed to set socket non-blocking for connection %s:%d", ipv4_str(ipv4), port);
        close_and_log(fd, ipv4, port);
        return;
    }

    struct tcp_conn* conn = malloc(server->conf->connection_buffer_size);
    if (conn == 0) {
        LOG_ERROR("Failed to allocate memory for new connection: %s:%d", ipv4_str(ipv4), port);
        close_and_log(fd, ipv4, port);
        return;
    }
    atomic_store_explicit(&conn->ref_count, 1, memory_order_release);
    atomic_store_explicit(&conn->is_closed, 0, memory_order_release);
    conn->server = server;
    conn->fd = fd;
    if (server->tls_ctx != 0) {
        conn->tls = new_tls_for_conn(server->tls_ctx, fd);
        if (conn->tls == 0) {
            free(conn);
            close_and_log(fd, ipv4, port);
            return;
        }
    } else {
        conn->tls = 0;
    }
    conn->user_data = 0;
    conn->ipv4 = ipv4;
    conn->port = port;
    tcp_write_loop_add_conn(&server->w_loop, conn);

    if (event_loop_add_read_fd(&server->r_loop, conn->fd, conn) < 0) {
        LOG_ERROR("Could not accept TCP connection from %s:%d (fd=%d), %s failed errno=%d (%s)", ipv4_str(conn->ipv4),
                  conn->port, conn->fd, event_loop_ctl_syscall_name, errno, errno_str(errno));
        close_tcp_conn_in_loop(conn);
        return;
    }

    LOG_DEBUG("TCP client connected: %s:%d (fd=%d)", ipv4_str(conn->ipv4), conn->port, conn->fd);
}

static void recv_from_tcp_conn(struct tcp_conn* conn) {
    if (atomic_load_explicit(&conn->is_closed, memory_order_acquire) != 0) {
        LOG_DEBUG("Connection %s:%d (fd=%d) is already closed, ignoring recv request", ipv4_str(conn->ipv4), conn->port,
                  conn->fd);
        return;
    }

    int num_bytes;
    if (conn->tls == 0) {
        num_bytes = recv(conn->fd, conn->buf, tcp_conn_buf_cap(conn->server), MSG_DONTWAIT);
        if (num_bytes < 0) {
            LOG_ERROR("recv() on connection %s:%d (fd=%d) failed, errno=%d (%s)", ipv4_str(conn->ipv4), conn->port,
                      conn->fd, errno, errno_str(errno));
        }
    } else {
        enum recv_tls_result result = recv_tls(conn->tls, conn->buf, tcp_conn_buf_cap(conn->server), &num_bytes);
        if (result == recv_tls_retry) {
            return;
        }
    }
    if (num_bytes <= 0) {
        close_tcp_conn_in_loop(conn);
        return;
    }
    LOG_DEBUG("Received %d bytes from %s:%d (fd=%d)", num_bytes, ipv4_str(conn->ipv4), conn->port, conn->fd);
    conn->buf[num_bytes] = 0;
    if (conn->server->on_conn_recv(conn->server->data, conn, num_bytes) < 0) {
        close_tcp_conn_in_loop(conn);
    }
}

struct tcp_server_notification {
    enum
    { ts_notify_close_conn, } type;
    void* data;
};

static int process_notification_cb(void* cb_data) {
    struct tcp_server* server = (struct tcp_server*)cb_data;
    struct tcp_server_notification notification;
    event_loop_recv_notification(&server->r_loop, &notification, sizeof(notification));
    if (notification.type == ts_notify_close_conn) {
        struct tcp_conn* conn = notification.data;
        close_tcp_conn_in_loop(conn);
    }
    return 0;
}

static int process_event_cb(void* data, int flags, void* cb_data) {
    struct tcp_server* server = (struct tcp_server*)cb_data;
    if (data == &server->listen_fd) {
        LOG_DEBUG("Received kevent on TCP server socket (fd=%d)", server->listen_fd);
        accept_tcp_conn(server);
    } else {
        struct tcp_conn* conn = (struct tcp_conn*)data;
        if (flags & evf_eof) {
            close_tcp_conn_in_loop(conn);
        } else if (flags & evf_read) {
            LOG_DEBUG("Received read kevent on connection %s:%d (fd=%d)", ipv4_str(conn->ipv4), conn->port, conn->fd);
            recv_from_tcp_conn(conn);
        }
    }
    return 0;
}

void run_tcp_server_loop(struct tcp_server* server) {
    int run_status = event_loop_run(&server->r_loop, server, process_event_cb, process_notification_cb);
    if (run_status != 0) {
        if (run_status < 0) {
            LOG_FATAL("TCP read event loop failed: %s failed errno=%d (%s)", event_loop_run_syscall_name, errno,
                      errno_str(errno));
        } else {
            LOG_FATAL("TCP read event loop failed: event processing callback returned error code=%d (%s)", run_status,
                      errno_str(run_status));
        }
    }
}

void tcp_conn_add_write_task(struct tcp_conn* conn, const char* buf, int buf_len, struct http_req* req, void* data,
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

void tcp_conn_inc_refcount(struct tcp_conn* conn) {
    atomic_fetch_add_explicit(&conn->ref_count, 1, memory_order_release);
}

void tcp_conn_dec_refcount(struct tcp_conn* conn) {
    int ref_cnt = atomic_fetch_sub_explicit(&conn->ref_count, 1, memory_order_acq_rel);
    if (ref_cnt == 1) {
        LOG_DEBUG("Reclaiming memory and file descriptor for tcp connection %s:%d (fd=%d)", ipv4_str(conn->ipv4),
                  conn->port, conn->fd);
        free_tls(conn->tls);
        close_and_log(conn->fd, conn->ipv4, conn->port);
        free(conn);
    }
}

void close_tcp_conn(struct tcp_conn* conn) {
    if (atomic_exchange_explicit(&conn->is_closed, 1, memory_order_acq_rel) == 1) {
        LOG_DEBUG("Trying to close TCP connection that is already closed %s:%d (fd=%d)", ipv4_str(conn->ipv4),
                  conn->port, conn->fd);
        return;
    }

    struct tcp_server_notification notification;
    notification.type = ts_notify_close_conn;
    notification.data = conn;
    event_loop_send_notification(&conn->server->r_loop, &notification, sizeof(notification));
}
