#ifndef NDC_HTTP_H_
#define NDC_HTTP_H_

#include "conf.h"

#include <pthread.h>

struct tcp_conn;

struct http_req {
    /// The underlying TCP connection.
    struct tcp_conn* conn;

    /// Null-terminated string pointing to the method of the request, inside the buffer.
    char* method;

    /// Null-terminated string pointing to the path of the request, inside the buffer.
    char* path;

    /// Null-terminated string pointing to the HTTP version of the request, inside the buffer.
    char* version;

    /// Null-terminated string pointing to the first HTTP header of the request, inside the buffer.
    char* headers;

    /// Pointer to the body of the request. Not necessarily null-terminated.
    char* body;

    /// Parsed value of the Content-Length header (-1 if the header is not available or invalid).
    int body_len;

    /// Used length of the request buffer.
    int buf_len;

    /// Maximum length of the request buffer.
    int buf_cap;

    /// The bytes of a HTTP request.
    /// The request is copied into this string. The memory here is owned by the request handler and
    /// must be freed after the the response is streamed.
    char* buf;

    /// For the queue of http requests.
    struct http_req* next;
};

struct http_server {
    struct http_req* head;
    struct http_req* tail;

    pthread_mutex_t lock;
    pthread_cond_t cond_var;
    _Atomic(int) stopped;

    void* cb_data;

    int req_buf_cap;

    int num_workers;
    pthread_t* workers;
};

/// Initialize a http server. Note: Aborts on failure.
void init_http_server(struct http_server* server, const struct http_conf* conf);

void delete_http_req(struct http_req* req);

// These callbacks are not implemented in the HTTP server.

void on_http_req_callback(void* cb_data, struct http_req* req);

#endif
