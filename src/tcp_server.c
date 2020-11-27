#include "tcp_server.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "logging.h"

struct tcp_conn_table_bucket {
    int size;
    int capacity;
    struct tcp_conn** entries;
};

struct tcp_conn_table {
    int size;
    int n_buckets;
    struct tcp_conn_table_bucket* buckets;
};

static struct tcp_conn_table* new_tcp_conn_table(int n_buckets, int bucket_init_cap) {
    struct tcp_conn_table* conn_table = malloc(sizeof(struct tcp_conn_table));
    if (conn_table == 0) {
        return 0;
    }
    conn_table->size = 0;
    conn_table->n_buckets = n_buckets;
    conn_table->buckets = malloc(sizeof(struct tcp_conn_table_bucket) * n_buckets);
    if (conn_table->buckets == 0) {
        free(conn_table);
        return 0;
    }
    for (int i = 0; i < conn_table->n_buckets; i++) {
        conn_table->buckets[i].size = 0;
        conn_table->buckets[i].capacity = bucket_init_cap;
        conn_table->buckets[i].entries = malloc(sizeof(void*) * conn_table->buckets[i].capacity);
        if (conn_table->buckets[i].entries == 0) {
            for (int j = 0; j < i; j++) {
                free(conn_table->buckets[j].entries);
            }
            free(conn_table->buckets);
            free(conn_table);
            return 0;
        }
    }
    return conn_table;
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

static int tcp_conn_table_erase(struct tcp_conn_table* conn_table, struct tcp_conn* conn) {
    int bucket_id = conn->fd % conn_table->n_buckets;
    struct tcp_conn_table_bucket* bucket = &conn_table->buckets[bucket_id];
    for (int i = 0; i < bucket->size; i++) {
        if (bucket->entries[i] == conn) {
            bucket->entries[i] = bucket->entries[bucket->size - 1];
            bucket->size -= 1;
            conn_table->size -= 1;
            return 0;
        }
    }
    return -1;
}

struct tcp_conn* find_tcp_conn(struct tcp_server* server, int fd) {
    int bucket_id = fd % server->conn_table->n_buckets;
    struct tcp_conn_table_bucket* bucket = &server->conn_table->buckets[bucket_id];
    for (int i = 0; i < bucket->size; i++) {
        if (bucket->entries[i]->fd == fd) {
            return bucket->entries[i];
        }
    }
    return 0;
}

struct tcp_server* init_tcp_server(int port, int max_clients, int n_buckets, int bucket_init_cap, int conn_buf_len,
                                   void* user_data) {
    struct tcp_server* server = malloc(sizeof(struct tcp_server));
    if (server == 0) {
        LOG_ERROR("Failed to allocate memory for tcp server structure");
        return 0;
    }

    struct tcp_conn_table* conn_table = new_tcp_conn_table(n_buckets, bucket_init_cap);
    if (conn_table == 0) {
        LOG_ERROR("Failed to allocate memory for tcp server connections table structure");
        return 0;
    }

    int listen_fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_fd < 0) {
        LOG_ERROR("socket() failed errno=%d (%s)", errno, strerror(errno));
        free(server);
        return 0;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(struct sockaddr_in));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(port);
    if (bind(listen_fd, (const struct sockaddr*)&server_addr, sizeof(struct sockaddr_in)) < 0) {
        LOG_ERROR("bind() failed errno=%d (%s)", errno, strerror(errno));
        if (close(listen_fd) < 0) {
            LOG_ERROR("close() failed errno=%d (%s)", errno, strerror(errno));
        }
        free(server);
        return 0;
    }

    if (listen(listen_fd, max_clients) < 0) {
        LOG_ERROR("listen() failed errno=%d (%s)", errno, strerror(errno));
        if (close(listen_fd) < 0) {
            LOG_ERROR("close() failed errno=%d (%s)", errno, strerror(errno));
        }
        free(server);
        return 0;
    }

    server->conn_table = conn_table;
    server->listen_fd = listen_fd;
    server->port = port;
    server->conn_buf_len = conn_buf_len;
    server->user_data = user_data;
    return server;
}

struct tcp_conn* accept_tcp_conn(struct tcp_server* server) {
    int fd;
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(struct sockaddr_in);
    fd = accept(server->listen_fd, (struct sockaddr*)&client_addr, &client_addr_len);
    if (fd < 0) {
        // TODO: Handle error better.
        LOG_FATAL("accept() failed errno=%d (%s)", errno, strerror(errno));
    }

    int ipv4 = client_addr.sin_addr.s_addr;
    int port = client_addr.sin_port;

    struct tcp_conn* conn = malloc(sizeof(struct tcp_conn));
    if (conn == 0) {
        LOG_ERROR("Failed to allocate memory for new connection: %s:%d", ipv4_str(ipv4), port);
        if (close(fd) < 0) {
            LOG_ERROR("Failed to close file descriptor %d for connection %s:%d, errno=%d (%s)", fd, ipv4_str(ipv4),
                      port, errno, strerror(errno));
        }
        return 0;
    }
    atomic_store_explicit(&conn->ref_count, 1, memory_order_release);
    conn->fd = fd;
    conn->buf_len = 0;
    conn->buf_cap = server->conn_buf_len;
    conn->buf = malloc(conn->buf_cap + 1);
    if (conn->buf == 0) {
        LOG_ERROR("Failed to allocate buffer for new connection: %s:%d", ipv4_str(ipv4), port);
        if (close(fd) < 0) {
            LOG_ERROR("Failed to close file descriptor %d for connection %s:%d, errno=%d (%s)", fd, ipv4_str(ipv4),
                      port, errno, strerror(errno));
        }
        free(conn);
        return 0;
    }
    conn->user_data = 0;
    conn->ipv4 = ipv4;
    conn->port = port;
    if (tcp_conn_table_insert(server->conn_table, conn) < 0) {
        LOG_ERROR("Failed to grow tcp connection table bucket");
        if (close(fd) < 0) {
            LOG_ERROR("Failed to close file descriptor %d for connection %s:%d, errno=%d (%s)", fd, ipv4_str(ipv4),
                      port, errno, strerror(errno));
        }
        free(conn->buf);
        free(conn);
        return 0;
    }
    if (tcp_conn_after_open_callback(server->user_data, conn) < 0) {
        if (close(fd) < 0) {
            LOG_ERROR("Failed to close file descriptor %d for connection %s:%d, errno=%d (%s)", fd, ipv4_str(ipv4),
                      port, errno, strerror(errno));
        }
        free(conn->buf);
        free(conn);
        return 0;
    }
    LOG_DEBUG("TCP client connected: %s:%d (fd=%d)", ipv4_str(conn->ipv4), conn->port, conn->fd);
    return conn;
}

int recv_from_tcp_conn(struct tcp_server* server, struct tcp_conn* conn) {
    int num_bytes = recv(conn->fd, conn->buf + conn->buf_len, conn->buf_cap - conn->buf_len, MSG_DONTWAIT);
    if (num_bytes < 0) {
        // TODO: Handle error better.
        LOG_FATAL("recv() on connection %s:%d (fd=%d) failed, errno=%d (%s)", ipv4_str(conn->ipv4), conn->port,
                  conn->fd, errno, strerror(errno));
    }
    if (num_bytes == 0) {
        return 0;
    }
    LOG_DEBUG("Received %d bytes from %s:%d (fd=%d)", num_bytes, ipv4_str(conn->ipv4), conn->port, conn->fd);
    conn->buf_len += num_bytes;
    conn->buf[conn->buf_len] = 0;
    if (tcp_conn_on_recv_callback(server->user_data, conn) < 0) {
        close_tcp_conn(server, conn);
    } else if (conn->buf_len == conn->buf_cap) {
        LOG_ERROR("Buffer full for connection %s:%d (fd=%d), will close connection", ipv4_str(conn->ipv4), conn->port,
                  conn->fd);
        close_tcp_conn(server, conn);
    }
    return 1;
}

void close_tcp_conn(struct tcp_server* server, struct tcp_conn* conn) {
    if (tcp_conn_before_close_callback(server->user_data, conn) < 0) {
        // If the client fails to close the connection on their part,
        // leak the connection rather than break the application.
        return;
    }
    if (tcp_conn_table_erase(server->conn_table, conn) < 0) {
        LOG_ERROR(
            "connection %s:%d (fd=%d) is not in TCP connections table. Memory for this "
            "connection will not be reclaimed, so this message may indicate a memory leak.",
            ipv4_str(conn->ipv4), conn->port, conn->fd);
        return;
    }
    if (close(conn->fd) < 0) {
        LOG_ERROR("Failed to close file descriptor %d for connection %s:%d, errno=%d (%s)", conn->fd,
                  ipv4_str(conn->ipv4), conn->port, errno, strerror(errno));
    }
    LOG_DEBUG("TCP client disconnected: %s:%d (fd=%d)", ipv4_str(conn->ipv4), conn->port, conn->fd);
    tcp_conn_dec_refcount(conn);
}

void tcp_conn_inc_refcount(struct tcp_conn* conn) {
    atomic_fetch_add_explicit(&conn->ref_count, 1, memory_order_release);
}

void tcp_conn_dec_refcount(struct tcp_conn* conn) {
    int ref_cnt = atomic_fetch_sub_explicit(&conn->ref_count, 1, memory_order_acq_rel);
    if (ref_cnt == 1) {
        LOG_DEBUG("Reclaiming memory for tcp connection %s:%d (fd=%d)", ipv4_str(conn->ipv4), conn->port, conn->fd);
        free(conn->buf);
        free(conn);
    }
}
