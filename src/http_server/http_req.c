#include "http_req.h"

#include "../logging/logging.h"
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
