#include "static_file_server.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../http_server/http_server.h"
#include "../../logging/logging.h"
#include "file_cache.h"

static const char* http_404_response =
    "HTTP/1.1 404 Not found\r\n"
    "Server: NDC/1.0.0\r\n"
    "Connection: Close\r\n"
    "Content-Length: 0\r\n"
    "\r\n";
static const int http_404_response_len = 83;

#define NUM_KNOWN_EXTENSIONS 5
struct known_extension {
    const char* ext;
    int ext_len;
    const char* content_type;
};
static struct known_extension known_extensions[NUM_KNOWN_EXTENSIONS] = {
    {.ext = ".txt", .ext_len = 4, .content_type = "text/plain; charset=UTF-8"},
    {.ext = ".json", .ext_len = 5, .content_type = "application/json; charset=UTF-8"},
    {.ext = ".html", .ext_len = 5, .content_type = "text/html; charset=UTF-8"},
    {.ext = ".htm", .ext_len = 4, .content_type = "text/html; charset=UTF-8"},
    {.ext = ".xml", .ext_len = 4, .content_type = "text/xml"},
};

void init_static_file_server(struct static_file_server* server, struct file_cache* cache,
                             struct http_server* http_server, const char* base_dir) {
    server->http_server = http_server;
    server->cache = cache;
    server->base_dir_len = strlen(base_dir);
    server->base_dir = malloc(server->base_dir_len + 1);
    if (server->base_dir == 0) {
        LOG_FATAL("Failed to allocate memory for static file server base_dir string.");
    }
    strcpy(server->base_dir, base_dir);
}

struct http_write_cb_data {
    struct http_req* req;
    struct static_file_server* server;
    struct mapped_file* file;

    int res_hdrs_len;
    char res_hdrs[200];
};

static void http_404_write_cb(void* data, int err) {
    struct http_write_cb_data* cb_data = (struct http_write_cb_data*)data;
    complete_http_req(cb_data->server->http_server, cb_data->req, 404, err);
    free(cb_data);
}

static void http_200_response_headers_cb(void* data, int err) {
    struct http_write_cb_data* cb_data = (struct http_write_cb_data*)data;
    if (err != 0) {
        LOG_ERROR("Failed to write 200 response headers to request %s %s from connection %s:%d errno=%d (%s)",
                  req_method(cb_data->req), req_path(cb_data->req), ipv4_str(cb_data->req->conn->ipv4),
                  cb_data->req->conn->port, err, errno_str(err));
    }
}

static void http_200_response_body_cb(void* data, int err) {
    struct http_write_cb_data* cb_data = (struct http_write_cb_data*)data;
    close_file(cb_data->server->cache, cb_data->file);
    complete_http_req(cb_data->server->http_server, cb_data->req, 200, err);
    free(cb_data);
}

void static_file_server_handle(void* data, struct http_req* req) {
    struct static_file_server* server = (struct static_file_server*)data;
    char* path = malloc(server->base_dir_len + strlen(req_path(req)) + 1);
    if (path == 0) {
        LOG_ERROR("Failed to allocate memory while responding to HTTP request %s:%d %s %s", ipv4_str(req->conn->ipv4),
                  req->conn->port, req_method(req), req_path(req));
        close_tcp_conn(&server->http_server->tcp_server, req->conn);
        complete_http_req(server->http_server, req, 0, 0);
        return;
    }

    struct http_write_cb_data* cb_data = malloc(sizeof(struct http_write_cb_data));
    if (cb_data == 0) {
        LOG_ERROR("Failed to allocate callback data for writing response to request %s %s from connection %s:%d",
                  req_method(req), req_path(req), ipv4_str(req->conn->ipv4), req->conn->port);
        close_tcp_conn(&server->http_server->tcp_server, req->conn);
        complete_http_req(server->http_server, req, 0, 0);
        return;
    }

    cb_data->req = req;
    cb_data->server = server;
    cb_data->file = 0;

    strcpy(path, server->base_dir);
    strcat(path, req_path(req) + (path[server->base_dir_len - 1] == '/' && req_path(req)[0] == '/' ? 1 : 0));

    struct mapped_file* file = open_file(server->cache, path);
    if (file == 0) {
        tcp_write_loop_push(&server->http_server->tcp_server.w_loop, req->conn, http_404_response,
                            http_404_response_len, cb_data, http_404_write_cb);
        return;
    }
    cb_data->file = file;

    const char* content_type_hdr_value = "application/octet-stream";
    for (int i = 0; i < NUM_KNOWN_EXTENSIONS; i++) {
        if (file->path_len >= known_extensions[i].ext_len &&
            strcmp(file->path + (file->path_len - known_extensions[i].ext_len), known_extensions[i].ext) == 0) {
            content_type_hdr_value = known_extensions[i].content_type;
            break;
        }
    }

    cb_data->res_hdrs_len = snprintf(cb_data->res_hdrs, 200,
                                     "HTTP/1.1 200 OK\r\n"
                                     "Server: NDC/1.0.0\r\n"
                                     "Content-Type: %s\r\n"
                                     "Content-Length: %d\r\n"
                                     "\r\n",
                                     content_type_hdr_value, file->content_len);
    if (cb_data->res_hdrs_len < 0) {
        LOG_ERROR("Failed to format response headers of request %s %s from connection %s:%d: snprintf returned %d",
                  req_method(req), req_path(req), ipv4_str(req->conn->ipv4), req->conn->port, cb_data->res_hdrs_len);
        free(cb_data);
        close_file(server->cache, file);
        close_tcp_conn(&server->http_server->tcp_server, req->conn);
        complete_http_req(server->http_server, req, 0, 0);
        return;
    }
    tcp_write_loop_push(&server->http_server->tcp_server.w_loop, req->conn, cb_data->res_hdrs, cb_data->res_hdrs_len,
                        cb_data, http_200_response_headers_cb);
    tcp_write_loop_push(&server->http_server->tcp_server.w_loop, req->conn, file->content, file->content_len, cb_data,
                        http_200_response_body_cb);
}
