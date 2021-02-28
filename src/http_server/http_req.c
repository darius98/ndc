#include "http_req.h"

#include <stdlib.h>

#include "../logging/logging.h"
#include "http_server.h"
#include "tcp_server.h"

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

void http_response_write(struct http_req* req, const char* buf, int buf_len, void* data, write_task_cb cb) {
    tcp_write_loop_push(&req->server->tcp_server.w_loop, req->conn, buf, buf_len, data, cb);
}

void http_response_end(struct http_req* req, int status, int error) {
    if (error != 0) {
        LOG_ERROR("Failed to write %d response to request %s %s from connection %s:%d error=%d (%s)", status,
                  req_method(req), req_path(req), req_remote_ipv4(req), req_remote_port(req), error, errno_str(error));
    } else if (status != 0) {
        log_access(req, status);
    }
    tcp_conn_dec_refcount(req->conn);
    free(req->buf);
    free(req);
}

void http_response_fail(struct http_req* req) {
    close_tcp_conn(&req->server->tcp_server, req->conn);
    http_response_end(req, 0, 0);
}
