#include "tcp_conn_table.h"

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

    int conn_buf_len;
};

struct tcp_conn_table* new_tcp_conn_table(int n_buckets, int bucket_init_cap, int conn_buf_len) {
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
    conn_table->conn_buf_len = conn_buf_len;
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

struct tcp_conn* tcp_conn_table_lookup(struct tcp_conn_table* conn_table, int fd) {
    int bucket_id = fd % conn_table->n_buckets;
    struct tcp_conn_table_bucket* bucket = &conn_table->buckets[bucket_id];
    for (int i = 0; i < bucket->size; i++) {
        if (bucket->entries[i]->fd == fd) {
            return bucket->entries[i];
        }
    }
    return 0;
}

struct tcp_conn* new_tcp_conn(struct tcp_conn_table* conn_table, int fd, int ipv4, int port) {
    struct tcp_conn* conn = malloc(sizeof(struct tcp_conn));
    if (conn == 0) {
        LOG_ERROR("Failed to allocate memory for new connection: %s:%d", ipv4_str(ipv4), port);
        return 0;
    }
    conn->buf_cap = conn_table->conn_buf_len;
    conn->buf_len = 0;
    conn->buf = malloc(conn->buf_cap + 1);
    if (conn->buf == 0) {
        LOG_ERROR("Failed to allocate buffer for new connection: %s:%d", ipv4_str(ipv4), port);
        free(conn);
        return 0;
    }
    conn->cur_req = 0;
    conn->fd = fd;
    conn->ipv4 = ipv4;
    conn->port = port;
    if (tcp_conn_table_insert(conn_table, conn) < 0) {
        LOG_ERROR("Failed to grow tcp connection table bucket");
        free(conn->buf);
        free(conn);
        return 0;
    }
    return conn;
}

void close_tcp_conn(struct http_req_queue* req_queue, struct tcp_conn_table* conn_table, struct tcp_conn* conn) {
    if (tcp_conn_table_erase(conn_table, conn) < 0) {
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
    if (conn->cur_req != 0) {
        delete_http_req(req_queue, conn->cur_req);
        conn->cur_req = 0;
    }
    tcp_conn_dec_refcount(req_queue, conn);
}

void tcp_conn_inc_refcount(struct tcp_conn* conn) {
    atomic_fetch_add_explicit(&conn->ref_count, 1, memory_order_release);
}

void tcp_conn_dec_refcount(struct http_req_queue* req_queue, struct tcp_conn* conn) {
    int ref_cnt = atomic_fetch_sub_explicit(&conn->ref_count, 1, memory_order_acq_rel);
    if (ref_cnt == 1) {
        LOG_DEBUG("Reclaiming memory for tcp connection %s:%d (fd=%d)", ipv4_str(conn->ipv4), conn->port, conn->fd);
        free(conn->buf);
        free(conn);
    }
}
