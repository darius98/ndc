#ifndef NDC_HTTP_SERVER_HTTP_REQ_H_
#define NDC_HTTP_SERVER_HTTP_REQ_H_

#include "utils/config.h"
#include "tcp/tcp_server.h"

NDC_BEGIN_DECLS

struct http_server;

enum http_req_parse_state {
    req_parse_state_method = 0,
    req_parse_state_path = 1,
    req_parse_state_version = 2,
    req_parse_state_headers = 3,
    req_parse_state_body = 4,
    req_parse_state_done = 5,
};

struct http_req {
    struct http_server* server;

    /// The underlying TCP connection.
    struct tcp_conn* conn;

    enum http_req_parse_state parse_state;

    int path_offset;
    int version_offset;
    int headers_offset;
    int body_offset;
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

int req_remote_port(struct http_req* req);

const char* req_remote_ipv4(struct http_req* req);

char* req_method(struct http_req* req);

char* req_path(struct http_req* req);

char* req_version(struct http_req* req);

char* req_headers(struct http_req* req);

char* req_body(struct http_req* req);

void http_response_write(struct http_req* req, const char* buf, int buf_len, void* data, tcp_conn_write_cb cb);

void http_response_end(struct http_req* req, int status);

void http_response_fail(struct http_req* req);

NDC_END_DECLS

#endif
