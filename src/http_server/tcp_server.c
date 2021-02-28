#include "tcp_server.h"

#include <errno.h>
#include <netinet/in.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../logging/logging.h"
#include "../utils/fd.h"
#include "tcp_write_loop.h"
#include "tls.h"

void init_tcp_server(struct tcp_server* server, int port, const struct tcp_server_conf* conf,
                     const struct tcp_write_loop_conf* w_loop_conf, void* cb_data, on_conn_open_cb on_conn_open,
                     on_conn_recv_cb on_conn_recv, on_conn_closed_cb on_conn_closed) {
    init_tcp_write_loop(&server->w_loop, w_loop_conf, server);
    server->tls_ctx = init_tls(conf->tls_cert_pem);
    server->conf = conf;
    server->port = port;
    server->cb_data = cb_data;
    server->on_conn_open = on_conn_open;
    server->on_conn_recv = on_conn_recv;
    server->on_conn_closed = on_conn_closed;

    if (make_nonblocking_pipe(server->notify_pipe) < 0) {
        LOG_FATAL("Failed to create notify pipe for TCP server");
    }

    server->listen_fd = listen_tcp(port, conf->backlog);
    if (server->listen_fd < 0) {
        LOG_FATAL("Failed to start TCP server");
    }
}

static void close_and_log(int fd, int ipv4, int port) {
    if (close(fd) < 0) {
        LOG_ERROR("Failed to close file descriptor %d for connection %s:%d, errno=%d (%s)", fd, ipv4_str(ipv4), port,
                  errno, errno_str(errno));
    }
}

static int tcp_conn_buf_cap(struct tcp_server* server) {
    return (int)(server->conf->connection_buffer_size - sizeof(struct tcp_conn) - 1);
}

struct tcp_conn* accept_tcp_conn(struct tcp_server* server) {
    int fd;
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(struct sockaddr_in);
    fd = accept(server->listen_fd, (struct sockaddr*)&client_addr, &client_addr_len);
    if (fd < 0) {
        LOG_ERROR("Failed to accept new TCP connection: accept() failed errno=%d (%s)", errno, errno_str(errno));
        return 0;
    }

    int ipv4 = client_addr.sin_addr.s_addr;
    int port = client_addr.sin_port;

    if (set_nonblocking(fd) < 0) {
        LOG_ERROR("Failed to set socket non-blocking for connection %s:%d", ipv4_str(ipv4), port);
        close_and_log(fd, ipv4, port);
        return 0;
    }

    struct tcp_conn* conn = malloc(server->conf->connection_buffer_size);
    if (conn == 0) {
        LOG_ERROR("Failed to allocate memory for new connection: %s:%d", ipv4_str(ipv4), port);
        close_and_log(fd, ipv4, port);
        return 0;
    }
    atomic_store_explicit(&conn->ref_count, 1, memory_order_release);
    conn->fd = fd;
    if (server->tls_ctx != 0) {
        conn->tls = new_tls_for_conn(server->tls_ctx, fd);
        if (conn->tls == 0) {
            free(conn);
            close_and_log(fd, ipv4, port);
            return 0;
        }
    } else {
        conn->tls = 0;
    }
    conn->user_data = 0;
    conn->ipv4 = ipv4;
    conn->port = port;
    atomic_store_explicit(&conn->is_closed, 0, memory_order_release);
    tcp_write_loop_add_conn(&server->w_loop, conn);
    if (server->on_conn_open(server->cb_data, conn) < 0) {
        tcp_write_loop_remove_conn(&server->w_loop, conn);
        free_tls(conn->tls);
        free(conn);
        close_and_log(fd, ipv4, port);
        return 0;
    }
    LOG_DEBUG("TCP client connected: %s:%d (fd=%d)", ipv4_str(conn->ipv4), conn->port, conn->fd);
    return conn;
}

void recv_from_tcp_conn(struct tcp_server* server, struct tcp_conn* conn) {
    if (atomic_load_explicit(&conn->is_closed, memory_order_acquire) != 0) {
        LOG_DEBUG("Connection %s:%d (fd=%d) is already closed, ignoring recv request", ipv4_str(conn->ipv4), conn->port,
                  conn->fd);
        return;
    }

    int num_bytes;
    if (conn->tls == 0) {
        num_bytes = recv(conn->fd, conn->buf, tcp_conn_buf_cap(server), MSG_DONTWAIT);
        if (num_bytes < 0) {
            LOG_ERROR("recv() on connection %s:%d (fd=%d) failed, errno=%d (%s)", ipv4_str(conn->ipv4), conn->port,
                      conn->fd, errno, errno_str(errno));
        }
    } else {
        enum recv_tls_result result = recv_tls(conn->tls, conn->buf, tcp_conn_buf_cap(server), &num_bytes);
        if (result == recv_tls_retry) {
            return;
        }
    }
    if (num_bytes <= 0) {
        close_tcp_conn_in_loop(server, conn);
        return;
    }
    LOG_DEBUG("Received %d bytes from %s:%d (fd=%d)", num_bytes, ipv4_str(conn->ipv4), conn->port, conn->fd);
    conn->buf[num_bytes] = 0;
    if (server->on_conn_recv(server->cb_data, conn, num_bytes) < 0) {
        close_tcp_conn_in_loop(server, conn);
    }
}

struct tcp_server_notification {
    enum
    { ts_notify_close_conn, } type;
    void* data;
};

void close_tcp_conn_in_loop(struct tcp_server* server, struct tcp_conn* conn) {
    server->on_conn_closed(server->cb_data, conn);
    tcp_write_loop_remove_conn(&server->w_loop, conn);
    remove_conn_from_read_loop(server, conn);
    LOG_DEBUG("TCP client disconnected: %s:%d (fd=%d)", ipv4_str(conn->ipv4), conn->port, conn->fd);
    tcp_conn_dec_refcount(conn);
}

void close_tcp_conn(struct tcp_server* server, struct tcp_conn* conn) {
    if (atomic_exchange_explicit(&conn->is_closed, 1, memory_order_acq_rel) == 1) {
        LOG_DEBUG("Trying to close TCP connection that is already closed %s:%d (fd=%d)", ipv4_str(conn->ipv4),
                  conn->port, conn->fd);
        return;
    }

    struct tcp_server_notification notification;
    notification.type = ts_notify_close_conn;
    notification.data = conn;
    int ret = write(server->notify_pipe[1], &notification, sizeof(struct tcp_server_notification));
    if (ret != sizeof(struct tcp_server_notification)) {
        if (ret < 0) {
            LOG_FATAL("Failed to write() to TCP server notify pipe errno=%d (%s)", errno, errno_str(errno));
        } else {
            LOG_FATAL("Failed to write() to TCP server notify pipe, wrote %d out of %d bytes.", ret,
                      (int)sizeof(struct tcp_server_notification));
        }
    }
}

void tcp_server_process_notification(struct tcp_server* server) {
    struct tcp_server_notification notification;
    errno = 0;
    ssize_t n_bytes = read(server->notify_pipe[0], &notification, sizeof(struct tcp_server_notification));
    if (n_bytes != sizeof(struct tcp_server_notification)) {
        LOG_FATAL("TCP server: failed to read from notify pipe, returned %d, errno=%d (%s)", (int)n_bytes, errno,
                  errno_str(errno));
    }
    if (notification.type == ts_notify_close_conn) {
        struct tcp_conn* conn = notification.data;
        close_tcp_conn_in_loop(server, conn);
    }
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
