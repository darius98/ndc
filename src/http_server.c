#include "http_server.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#include "logging.h"
#include "static_file_server.h"
#include "tcp_server.h"

struct http_server {
    struct http_req* head;
    struct http_req* tail;

    pthread_mutex_t lock;
    pthread_cond_t cond_var;
    atomic_int stopped;

    int req_buf_cap;

    int num_workers;
    pthread_t* workers;

    // Sub-servers
    struct static_file_server* static_files;
};

static void http_server_push_req(struct http_server* server, struct http_req* req) {
    int err = pthread_mutex_lock(&server->lock);
    if (err != 0) {
        LOG_FATAL("pthread_mutex_lock() failed with error=%d", err);
    }
    req->next = 0;
    if (server->tail != 0) {
        server->tail->next = req;
    }
    server->tail = req;
    if (server->head == 0) {
        server->head = req;
    }
    err = pthread_mutex_unlock(&server->lock);
    if (err != 0) {
        LOG_FATAL("pthread_mutex_unlock() failed with error=%d", err);
    }
    err = pthread_cond_signal(&server->cond_var);
    if (err != 0) {
        LOG_FATAL("pthread_cond_signal() failed with error=%d", err);
    }
}

static struct http_req* http_server_pop_req(struct http_server* server) {
    int err = pthread_mutex_lock(&server->lock);
    if (err != 0) {
        LOG_FATAL("pthread_mutex_lock() failed with error=%d", err);
    }
    err = pthread_cond_wait(&server->cond_var, &server->lock);
    if (err != 0) {
        LOG_FATAL("pthread_cond_wait() failed with error=%d", err);
    }
    struct http_req* req = server->head;
    if (req != 0) {
        server->head = req->next;
        if (server->head == 0) {
            server->tail = 0;
        }
        req->next = 0;
    }
    err = pthread_mutex_unlock(&server->lock);
    if (err != 0) {
        LOG_FATAL("pthread_mutex_unlock() failed with error=%d", err);
    }
    return req;
}

static void delete_http_req(struct http_server* server, struct http_req* req) {
    tcp_conn_dec_refcount(req->conn);
    free(req->buf);
    free(req);
}

static void* http_worker(void* arg) {
    struct http_server* server = (struct http_server*)arg;
    while (atomic_load_explicit(&server->stopped, memory_order_acquire) == 0) {
        struct http_req* req = http_server_pop_req(server);
        if (req != 0) {
            serve_static_file(server->static_files, req);
            delete_http_req(server, req);
        }
    }
    return 0;
}

struct http_server* new_http_server(struct static_file_server* static_files, int req_buf_cap, int num_workers) {
    struct http_server* server = malloc(sizeof(struct http_server));
    if (server == 0) {
        return 0;
    }
    server->req_buf_cap = req_buf_cap;
    server->static_files = static_files;
    server->head = 0;
    server->tail = 0;
    int err = pthread_mutex_init(&server->lock, 0);
    if (err != 0) {
        LOG_FATAL("pthread_mutex_init() failed with error=%d", err);
    }
    err = pthread_cond_init(&server->cond_var, 0);
    if (err != 0) {
        LOG_FATAL("pthread_cond_init() failed with error=%d", err);
    }
    atomic_store_explicit(&server->stopped, 0, memory_order_release);
    server->num_workers = num_workers;
    server->workers = malloc(num_workers * sizeof(pthread_t));
    if (server->workers == 0) {
        LOG_FATAL("Failed to allocate memory for HTTP workers.");
    }
    for (int i = 0; i < num_workers; i++) {
        err = pthread_create(&server->workers[i], 0, http_worker, server);
        if (err != 0) {
            LOG_FATAL("Failed to start HTTP worker error=%d", err);
        }
    }
    return server;
}

static struct http_req* new_http_req(struct http_server* server, struct tcp_conn* conn) {
    int ipv4 = conn->ipv4;
    int port = conn->port;
    struct http_req* req = malloc(sizeof(struct http_req));
    if (req == 0) {
        LOG_ERROR("Memory allocation failure: new http request, will close connection to %s:%d", ipv4_str(ipv4), port);
        return 0;
    }

    req->buf_len = 0;
    req->buf_cap = server->req_buf_cap;
    req->buf = malloc(req->buf_cap);
    if (req->buf == 0) {
        LOG_ERROR("Memory allocation failure: buffer for new http request, will close connection to %s:%d",
                  ipv4_str(ipv4), port);
        free(req);
        return 0;
    }

    req->conn = conn;
    tcp_conn_inc_refcount(conn);

    req->method = 0;
    req->path = 0;
    req->version = 0;
    req->body_len = -1;
    req->body = 0;
    req->next = 0;
    return req;
}

static char* append_to_http_req(struct http_req* req, char* start, char* end) {
    int len = end - start;
    if (len + 1 > req->buf_cap - req->buf_len) {
        LOG_ERROR("Received HTTP request larger than %d bytes from %s:%d, will close connection", req->buf_cap,
                  ipv4_str(req->conn->ipv4), req->conn->port);
        return 0;
    }
    char* dst = req->buf + req->buf_len;
    memcpy(dst, start, len);
    req->buf_len += len;
    req->buf[req->buf_len++] = 0;
    return dst;
}

static char* find_next_space(char* s) {
    return strchr(s, ' ');
}

static char* find_next_clrf(char* s) {
    return strstr(s, "\r\n");
}

static int read_http_reqs(struct http_server* server, struct tcp_conn* conn) {
    char* buf = conn->buf;
    char* initial_buf = buf;
    while (1) {
        struct http_req* req = conn->user_data;
        ASSERT(req != 0);

        if (req->method == 0) {
            char* end = find_next_space(buf);
            if (end == 0) {
                return buf - initial_buf;
            }
            char* method = append_to_http_req(req, buf, end);
            if (method == 0) {
                return -1;
            }
            req->method = method;
            buf = end + 1;
        }
        if (req->path == 0) {
            char* end = find_next_space(buf);
            if (end == 0) {
                return buf - initial_buf;
            }
            char* path = append_to_http_req(req, buf, end);
            if (path == 0) {
                return -1;
            }
            req->path = path;
            buf = end + 1;
        }
        if (req->version == 0) {
            char* end = find_next_clrf(buf);
            if (end == 0) {
                return buf - initial_buf;
            }
            char* version = append_to_http_req(req, buf, end);
            if (version == 0) {
                return -1;
            }
            req->version = version;
            req->headers = req->version + (end - buf) + 1;
            buf = end + 2;
        }
        while (1) {
            char* end = find_next_clrf(buf);
            if (end == 0) {
                return buf - initial_buf;
            }
            if (end == buf) {
                // headers are done.
                buf = end + 2;
                break;
            }
            // TODO: Parse Content-Length and other significant headers.
            if (append_to_http_req(req, buf, end) == 0) {
                return -1;
            }
            buf = end + 2;
            req->body = req->buf + req->buf_len;
        }
        if (req->body_len != -1) {
            // TODO: We still need to receive the request body.
        }
        // The request is fully parsed. Add it to the queue.
        http_server_push_req(server, req);
        conn->user_data = 0;

        req = new_http_req(server, conn);
        if (req == 0) {
            return -1;
        }
        conn->user_data = req;
    }
}

int tcp_conn_after_open_callback(void* cb_data, struct tcp_conn* conn) {
    struct http_req* req = new_http_req((struct http_server*)cb_data, conn);
    if (req == 0) {
        return -1;
    }
    conn->user_data = req;
    return 0;
}

int tcp_conn_on_recv_callback(void* cb_data, struct tcp_conn* conn) {
    int bytes_read = read_http_reqs((struct http_server*)cb_data, conn);
    if (bytes_read != conn->buf_len) {
        memmove(conn->buf, conn->buf + bytes_read, conn->buf_len - bytes_read);
    }
    conn->buf_len -= bytes_read;
    return bytes_read;
}

int tcp_conn_before_close_callback(void* cb_data, struct tcp_conn* conn) {
    if (conn->user_data != 0) {
        delete_http_req((struct http_server*)cb_data, (struct http_req*)conn->user_data);
        conn->user_data = 0;
    }
    return 0;
}
