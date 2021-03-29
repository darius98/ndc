#include "http_req.h"

#include <stdlib.h>

#include "access_log.h"
#include "http_server.h"
#include "logging/logging.h"
#include "tcp/tcp_server.h"

int req_remote_port(struct http_req* req) {
    return req->conn->port;
}

const char* req_remote_ipv4(struct http_req* req) {
    return ipv4_str(req->conn->ipv4);
}

char* req_method(struct http_req* req) {
    return req->buf;
}

char* req_path(struct http_req* req) {
    return req->buf + req->path_offset;
}

char* req_version(struct http_req* req) {
    return req->buf + req->version_offset;
}

char* req_headers(struct http_req* req) {
    return req->buf + req->headers_offset;
}

char* req_body(struct http_req* req) {
    return req->buf + req->body_offset;
}

void http_response_write(struct http_req* req, const char* buf, int buf_len, void* data, tcp_conn_write_cb cb) {
    tcp_conn_write(req->conn, buf, buf_len, data, cb);
}

void http_response_end(struct http_req* req, int status) {
    if (status != 0) {
        log_access(req, status);
    }
    tcp_conn_dec_refcount(req->conn);
    free(req->buf);
    free(req);
}

void http_response_fail(struct http_req* req) {
    tcp_conn_close(req->conn);
    http_response_end(req, 0);
}
