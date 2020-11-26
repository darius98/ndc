#include "http.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#include "logging.h"
#include "static_file_server.h"
#include "tcp_server.h"

struct http_req_queue {
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

static void http_req_queue_push(struct http_req_queue* req_queue, struct http_req* req) {
    int err = pthread_mutex_lock(&req_queue->lock);
    if (err != 0) {
        LOG_FATAL("pthread_mutex_lock() failed with error=%d", err);
    }
    req->next = 0;
    if (req_queue->tail != 0) {
        req_queue->tail->next = req;
    }
    req_queue->tail = req;
    if (req_queue->head == 0) {
        req_queue->head = req;
    }
    err = pthread_mutex_unlock(&req_queue->lock);
    if (err != 0) {
        LOG_FATAL("pthread_mutex_unlock() failed with error=%d", err);
    }
    err = pthread_cond_signal(&req_queue->cond_var);
    if (err != 0) {
        LOG_FATAL("pthread_cond_signal() failed with error=%d", err);
    }
}

static struct http_req* http_req_queue_pop(struct http_req_queue* req_queue) {
    int err = pthread_mutex_lock(&req_queue->lock);
    if (err != 0) {
        LOG_FATAL("pthread_mutex_lock() failed with error=%d", err);
    }
    err = pthread_cond_wait(&req_queue->cond_var, &req_queue->lock);
    if (err != 0) {
        LOG_FATAL("pthread_cond_wait() failed with error=%d", err);
    }
    struct http_req* req = req_queue->head;
    if (req != 0) {
        req_queue->head = req->next;
        if (req_queue->head == 0) {
            req_queue->tail = 0;
        }
        req->next = 0;
    }
    err = pthread_mutex_unlock(&req_queue->lock);
    if (err != 0) {
        LOG_FATAL("pthread_mutex_unlock() failed with error=%d", err);
    }
    return req;
}

static void delete_http_req(struct http_req_queue* req_queue, struct http_req* req) {
    tcp_conn_dec_refcount(req->conn);
    free(req->buf);
    free(req);
}

static void* http_worker(void* arg) {
    struct http_req_queue* req_queue = (struct http_req_queue*)arg;
    while (atomic_load_explicit(&req_queue->stopped, memory_order_acquire) == 0) {
        struct http_req* req = http_req_queue_pop(req_queue);
        if (req != 0) {
            serve_static_file(req_queue->static_files, req);
            delete_http_req(req_queue, req);
        }
    }
    return 0;
}

struct http_req_queue* new_http_req_queue(struct static_file_server* static_files, int req_buf_cap, int num_workers) {
    struct http_req_queue* queue = malloc(sizeof(struct http_req_queue));
    if (queue == 0) {
        return 0;
    }
    queue->req_buf_cap = req_buf_cap;
    queue->static_files = static_files;
    queue->head = 0;
    queue->tail = 0;
    int err = pthread_mutex_init(&queue->lock, 0);
    if (err != 0) {
        LOG_FATAL("pthread_mutex_init() failed with error=%d", err);
    }
    err = pthread_cond_init(&queue->cond_var, 0);
    if (err != 0) {
        LOG_FATAL("pthread_cond_init() failed with error=%d", err);
    }
    atomic_store_explicit(&queue->stopped, 0, memory_order_release);
    queue->num_workers = num_workers;
    queue->workers = malloc(num_workers * sizeof(pthread_t));
    if (queue->workers == 0) {
        LOG_FATAL("Failed to allocate memory for HTTP workers.");
    }
    for (int i = 0; i < num_workers; i++) {
        err = pthread_create(&queue->workers[i], 0, http_worker, queue);
        if (err != 0) {
            LOG_FATAL("Failed to start HTTP worker error=%d", err);
        }
    }
    return queue;
}

static struct http_req* new_http_req(struct http_req_queue* req_queue, struct tcp_conn* conn) {
    int ipv4 = conn->ipv4;
    int port = conn->port;
    struct http_req* req = malloc(sizeof(struct http_req));
    if (req == 0) {
        LOG_ERROR("Memory allocation failure: new http request, will close connection to %s:%d", ipv4_str(ipv4), port);
        return 0;
    }

    req->buf_len = 0;
    req->buf_cap = req_queue->req_buf_cap;
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

int tcp_conn_recv_callback(void* cb_data, struct tcp_conn* conn) {
    struct http_req_queue* req_queue = cb_data;
    char* buf = conn->buf;
    char* initial_buf = conn->buf;
    int bytes_read;
    while (1) {
        struct http_req* req = conn->user_data;
        if (req == 0) {
            req = new_http_req(req_queue, conn);
            if (req == 0) {
                // Errors logged inside new_http_req.
                return -1;
            }
            conn->user_data = req;
        }
        if (req->method == 0) {
            char* end = find_next_space(buf);
            if (end == 0) {
                goto done_parsing;
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
                goto done_parsing;
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
                goto done_parsing;
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
                goto done_parsing;
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
        http_req_queue_push(req_queue, req);
        conn->user_data = 0;
    }

done_parsing:
    bytes_read = buf - initial_buf;
    if (bytes_read != conn->buf_len) {
        memmove(conn->buf, conn->buf + bytes_read, conn->buf_len - bytes_read);
    }
    conn->buf_len -= bytes_read;
    return bytes_read;
}

void tcp_conn_before_close_callback(void* cb_data, struct tcp_conn* conn) {
    if (conn->user_data != 0) {
        delete_http_req((struct http_req_queue*)cb_data, (struct http_req*)conn->user_data);
        conn->user_data = 0;
    }
}
