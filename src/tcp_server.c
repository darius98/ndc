#include "tcp_server.h"

#include <errno.h>
#include <netinet/in.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "fd.h"
#include "logging.h"
#include "tls.h"
#include "write_queue.h"

static void init_tcp_conn_table(struct tcp_conn_table* conn_table, int n_buckets, int bucket_init_cap) {
    conn_table->size = 0;
    conn_table->n_buckets = n_buckets;
    conn_table->buckets = malloc(sizeof(struct tcp_conn_table_bucket) * n_buckets);
    if (conn_table->buckets == 0) {
        LOG_FATAL("Failed to allocate buckets for tcp_conn_table");
    }
    for (int i = 0; i < conn_table->n_buckets; i++) {
        conn_table->buckets[i].size = 0;
        conn_table->buckets[i].capacity = bucket_init_cap;
        conn_table->buckets[i].entries = malloc(sizeof(void*) * conn_table->buckets[i].capacity);
        if (conn_table->buckets[i].entries == 0) {
            LOG_FATAL("Failed to allocate entries for bucket %d of tcp_conn_table", i);
        }
    }
}

static int tcp_conn_table_insert(struct tcp_conn_table* conn_table, struct tcp_conn* conn) {
    int bucket_id = conn->fd % conn_table->n_buckets;
    struct tcp_conn_table_bucket* bucket = &conn_table->buckets[bucket_id];
    if (bucket->size == bucket->capacity) {
        void* resized = realloc(bucket->entries, sizeof(void*) * bucket->capacity * 2);
        if (resized == 0) {
            return -1;
        }
        bucket->entries = resized;
        bucket->capacity *= 2;
    }
    bucket->entries[bucket->size++] = conn;
    conn_table->size++;
    return 0;
}

static void tcp_conn_table_erase(struct tcp_conn_table* conn_table, struct tcp_conn* conn) {
    int bucket_id = conn->fd % conn_table->n_buckets;
    struct tcp_conn_table_bucket* bucket = &conn_table->buckets[bucket_id];
    for (int i = 0; i < bucket->size; i++) {
        if (bucket->entries[i] == conn) {
            bucket->entries[i] = bucket->entries[bucket->size - 1];
            bucket->size -= 1;
            conn_table->size -= 1;
            break;
        }
    }
}

struct tcp_conn* find_tcp_conn(struct tcp_server* server, int fd) {
    int bucket_id = fd % server->conn_table.n_buckets;
    struct tcp_conn_table_bucket* bucket = &server->conn_table.buckets[bucket_id];
    for (int i = 0; i < bucket->size; i++) {
        if (bucket->entries[i]->fd == fd) {
            return bucket->entries[i];
        }
    }
    return 0;
}

void init_tcp_server(struct tcp_server* server, int port, const struct tcp_server_conf* conf,
                     const struct tcp_write_queue_conf* w_queue_conf) {
    init_tcp_conn_table(&server->conn_table, conf->num_buckets, conf->bucket_initial_capacity);
    init_write_queue(&server->w_queue, w_queue_conf, server);
    server->tls_ctx = init_tls(conf->tls_cert_pem);
    server->conf = conf;
    server->port = port;

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
        LOG_ERROR("Failed to close file descriptor %d for connection %s:%d, errno=%d (%s)", fd, ipv4_str(ipv4),
                  port, errno, errno_str(errno));
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
    if (tcp_conn_table_insert(&server->conn_table, conn) < 0) {
        LOG_ERROR("Failed to grow tcp connection table bucket");
        free_tls(conn->tls);
        free(conn);
        close_and_log(fd, ipv4, port);
        return 0;
    }
    write_queue_add_conn(&server->w_queue, conn);
    if (tcp_conn_after_open_callback(server->cb_data, conn) < 0) {
        write_queue_remove_conn(&server->w_queue, conn);
        tcp_conn_table_erase(&server->conn_table, conn);
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
    if (tcp_conn_on_recv_callback(server->cb_data, conn, num_bytes) < 0) {
        close_tcp_conn_in_loop(server, conn);
    }
}

struct tcp_server_notification {
    enum
    { ts_notify_close_conn, } type;
    void* data;
};

void close_tcp_conn_in_loop(struct tcp_server* server, struct tcp_conn* conn) {
    tcp_conn_before_close_callback(server->cb_data, conn);
    tcp_conn_table_erase(&server->conn_table, conn);
    write_queue_remove_conn(&server->w_queue, conn);
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

void close_tcp_conn_by_fd(struct tcp_server* server, int fd) {
    struct tcp_conn* conn = find_tcp_conn(server, fd);
    if (conn == 0) {
        return;
    }
    if (atomic_exchange_explicit(&conn->is_closed, 1, memory_order_acq_rel) == 1) {
        LOG_DEBUG("Trying to close TCP connection that is already closed %s:%d (fd=%d)", ipv4_str(conn->ipv4),
                  conn->port, conn->fd);
        return;
    }
    LOG_DEBUG("Closing connection %s:%d (fd=%d) because of EOF kevent", ipv4_str(conn->ipv4), conn->port, conn->fd);
    close_tcp_conn_in_loop(server, conn);
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
