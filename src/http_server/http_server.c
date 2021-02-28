#include "http_server.h"

#include <ctype.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#include "../logging/logging.h"
#include "tcp_server.h"

static void http_server_push_req(struct http_server* server, struct http_req* req) {
    LOG_DEBUG("Pushing HTTP request %s %s from %s:%d", req_method(req), req_path(req), ipv4_str(req->conn->ipv4),
              req->conn->port);
    ff_pthread_mutex_lock(&server->lock);
    req->next = 0;
    if (server->tail != 0) {
        server->tail->next = req;
    }
    server->tail = req;
    if (server->head == 0) {
        server->head = req;
    }
    ff_pthread_mutex_unlock(&server->lock);
    ff_pthread_cond_signal(&server->cond_var);
}

static struct http_req* http_server_pop_req(struct http_server* server) {
    struct http_req* req;
    ff_pthread_mutex_lock(&server->lock);
    while (1) {
        req = server->head;
        if (req == 0) {
            ff_pthread_cond_wait(&server->cond_var, &server->lock);
        } else {
            server->head = req->next;
            if (server->head == 0) {
                server->tail = 0;
            }
            req->next = 0;
            break;
        }
    }
    ff_pthread_mutex_unlock(&server->lock);
    return req;
}

static void* http_worker(void* arg) {
    struct http_server* server = (struct http_server*)arg;
    while (atomic_load_explicit(&server->stopped, memory_order_acquire) == 0) {
        struct http_req* req = http_server_pop_req(server);
        LOG_DEBUG("Processing HTTP request %s %s from %s:%d", req_method(req), req_path(req), ipv4_str(req->conn->ipv4),
                  req->conn->port);
        for (int i = 0; i < server->handlers_len; i++) {
            if (server->handlers[i].should_handle(server->handlers[i].data, req)) {
                LOG_DEBUG("Request %s %s from %s:%d processed by handler %s", req_method(req), req_path(req),
                          ipv4_str(req->conn->ipv4), req->conn->port, server->handlers[i].name);
                server->handlers[i].handle(server->handlers[i].data, req);
                break;
            }
        }
    }
    return 0;
}

void init_http_server(struct http_server* server, const struct http_conf* conf) {
    server->head = 0;
    server->tail = 0;
    server->req_buf_cap = conf->request_buffer_size;
    ff_pthread_mutex_init(&server->lock, 0);
    ff_pthread_cond_init(&server->cond_var, 0);
    atomic_store_explicit(&server->stopped, 0, memory_order_release);
    server->handlers_len = 0;
    server->handlers_cap = 4;
    server->handlers = malloc(4 * sizeof(struct http_handler));
    if (server->handlers == 0) {
        LOG_FATAL("Failed to allocate memory for initial HTTP handlers array.");
    }
    server->num_workers = conf->num_workers;
    server->workers = malloc(conf->num_workers * sizeof(pthread_t));
    if (server->workers == 0) {
        LOG_FATAL("Failed to allocate memory for HTTP worker threads array.");
    }
    for (int i = 0; i < conf->num_workers; i++) {
        ff_pthread_create(&server->workers[i], 0, http_worker, server);
    }
}

void install_http_handler(struct http_server* server, struct http_handler handler) {
    if (server->handlers_len == server->handlers_cap) {
        void* resized = realloc(server->handlers, sizeof(struct http_handler) * server->handlers_cap * 2);
        if (resized == 0) {
            LOG_FATAL("Failed to grow HTTP handlers array");
        }
        server->handlers = resized;
        server->handlers_cap *= 2;
    }
    server->handlers[server->handlers_len++] = handler;
}

void complete_http_req(struct http_server* server, struct http_req* req, int status, int error) {
    if (error != 0) {
        LOG_ERROR("Failed to write %d response to request %s %s from connection %s:%d error=%d (%s)", status,
                  req_method(req), req_path(req), ipv4_str(req->conn->ipv4), req->conn->port, error, errno_str(error));
    } else if (status != 0) {
        log_access(req, status);
    }
    tcp_conn_dec_refcount(req->conn);
    free(req->buf);
    free(req);
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

    tcp_conn_inc_refcount(conn);

    req->conn = conn;
    req->parse_state = req_parse_state_method;
    req->path_offset = -1;
    req->version_offset = -1;
    req->body_len = -1;
    req->body_offset = -1;
    req->next = 0;
    return req;
}

static int safe_parse_unsigned_int(const char* start, const char* end) {
    // Skip any whitespace
    while (start != end && isspace(*start)) {
        ++start;
    }
    if (start == end) {
        return -1;
    }
    int n = 0;
    while (start != end && isdigit(*start)) {
        n = n * 10 + *start - '0';
        ++start;
    }
    if (start != end) {
        return -1;
    }
    return n;
}

static void try_parse_content_length_header(struct http_req* req, char* start, char* end) {
    if (end - start >= 16 && strncasecmp("Content-Length:", start, 15) == 0) {
        req->body_len = safe_parse_unsigned_int(start + 15, end);
    }
}

static int append_to_http_req(struct http_req* req, const char* start, const char* end) {
    int len = end - start;
    if (len > req->buf_cap - req->buf_len) {
        LOG_ERROR("Received HTTP request larger than %d bytes from %s:%d, will close connection", req->buf_cap,
                  ipv4_str(req->conn->ipv4), req->conn->port);
        return -1;
    }
    char* dst = req->buf + req->buf_len;
    memcpy(dst, start, len);
    req->buf_len += len;
    return 0;
}

static char* find_next_space(char* s) {
    return strchr(s, ' ');
}

static char* find_next_clrf(char* s) {
    return strstr(s, "\r\n");
}

static int read_http_reqs(struct http_server* server, struct tcp_conn* conn, int num_bytes) {
    char* buf = conn->buf;
    char* const buf_end = conn->buf + num_bytes;
    while (1) {
        struct http_req* req = conn->user_data;
        if (req->parse_state <= req_parse_state_method) {
            char* end = find_next_space(buf);
            if (end == 0) {
                if (append_to_http_req(req, buf, buf_end) < 0) {
                    return -1;
                }
                return 0;
            }
            *end = 0;
            if (append_to_http_req(req, buf, end + 1) < 0) {
                return -1;
            }
            buf = end + 1;
            req->parse_state = req_parse_state_path;
            req->path_offset = req->buf_len;
        }
        if (req->parse_state <= req_parse_state_path) {
            char* end = find_next_space(buf);
            if (end == 0) {
                if (append_to_http_req(req, buf, buf_end) < 0) {
                    return -1;
                }
                return 0;
            }
            *end = 0;
            if (append_to_http_req(req, buf, end + 1) < 0) {
                return -1;
            }
            buf = end + 1;
            req->parse_state = req_parse_state_version;
            req->version_offset = req->buf_len;
        }
        if (req->parse_state <= req_parse_state_version) {
            char* end = find_next_clrf(buf);
            if (end == 0) {
                if (append_to_http_req(req, buf, buf_end) < 0) {
                    return -1;
                }
                return 0;
            }
            *end = 0;
            *(end + 1) = 0;
            if (append_to_http_req(req, buf, end + 2) < 0) {
                return -1;
            }
            buf = end + 2;
            req->parse_state = req_parse_state_headers;
            req->headers_offset = req->buf_len;
        }
        while (1) {
            char* end = find_next_clrf(buf);
            if (end == 0) {
                if (append_to_http_req(req, buf, buf_end) < 0) {
                    return -1;
                }
                return 0;
            }
            *end = 0;
            *(end + 1) = 0;
            if (end == buf) {
                // headers are done.
                buf = end + 2;
                break;
            }
            if (append_to_http_req(req, buf, end + 2) < 0) {
                return -1;
            }
            try_parse_content_length_header(req, buf, end);
            buf = end + 2;
            req->body_offset = req->buf_len;
        }
        req->parse_state = req_parse_state_body;
        if (req->body_len > 0) {
            int body_len_read = req->buf_len - req->body_offset;
            int body_len_left = req->body_len - body_len_read;
            if (body_len_left >= 0) {
                // We still have to receive (at least part of) the request body.
                if (body_len_left >= req->buf_cap - req->buf_len) {
                    // We can't fit this request into the buffer.
                    return -1;
                }
                int recv_bytes_read = buf - conn->buf;
                int recv_bytes_left = num_bytes - recv_bytes_read;
                int body_bytes_recv = recv_bytes_left < body_len_left ? recv_bytes_left : body_len_left;
                memcpy(req->buf + req->buf_len, buf, body_bytes_recv);
                req->buf_len += body_bytes_recv;
                buf += body_bytes_recv;
                if (body_bytes_recv < body_len_left) {
                    return 0;
                }
            }
        }
        req->parse_state = req_parse_state_done;
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

int tcp_conn_on_recv_callback(void* cb_data, struct tcp_conn* conn, int num_bytes) {
    return read_http_reqs((struct http_server*)cb_data, conn, num_bytes);
}

void tcp_conn_before_close_callback(void* cb_data, struct tcp_conn* conn) {
    if (conn->user_data != 0) {
        complete_http_req((struct http_server*)cb_data, (struct http_req*)conn->user_data, 0, 0);
        conn->user_data = 0;
    }
}
