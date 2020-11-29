#include "static_file_server.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "file_cache.h"
#include "http_server.h"
#include "logging.h"
#include "tcp_server.h"
#include "write_queue.h"

struct static_file_server {
    struct file_cache* cache;
    int base_dir_len;
    char* base_dir;

    struct write_queue* write_queue;
};

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

struct static_file_server* new_static_file_server(const char* base_dir, int fcache_n_buckets,
                                                  int fcache_bucket_init_cap) {
    struct static_file_server* server = malloc(sizeof(struct static_file_server));
    if (server == 0) {
        LOG_FATAL("Failed to allocate memory for static file server");
    }
    server->cache = new_file_cache(fcache_n_buckets, fcache_bucket_init_cap);
    if (server->cache == 0) {
        LOG_FATAL("Failed to allocate memory for file cache");
    }
    server->base_dir_len = strlen(base_dir);
    server->base_dir = malloc(server->base_dir_len + 1);
    if (server->base_dir == 0) {
        LOG_FATAL("Failed to allocate memory for static file server base_dir string.");
    }
    strcpy(server->base_dir, base_dir);
    return server;
}

void static_file_server_set_write_queue(struct static_file_server* server, struct write_queue* queue) {
    server->write_queue = queue;
}

static struct mapped_file* find_file(struct static_file_server* server, struct http_req* req) {
    char* path = malloc(server->base_dir_len + strlen(req->path) + 1);
    if (path == 0) {
        LOG_ERROR("Failed to allocate memory while responding to HTTP request %s:%d %s %s", ipv4_str(req->conn->ipv4),
                  req->conn->port, req->method, req->path);
        return 0;
    }
    strcpy(path, server->base_dir);
    strcat(path, req->path + (path[server->base_dir_len - 1] == '/' && req->path[0] == '/' ? 1 : 0));
    return open_file(server->cache, path);
}

static void http_404_write_cb(void* data, struct tcp_conn* conn, int err) {
    struct http_req* req = (struct http_req*)data;
    if (err != 0) {
        LOG_ERROR("Failed to write 404 Not found response to request %s %s from connection %s:%d errno=%d (%s)",
                  req->method, req->path, ipv4_str(conn->ipv4), conn->port, err, strerror(err));
    } else {
        LOG_INFO("%s %s %s 404 Not found", ipv4_str(conn->ipv4), req->method, req->path);
    }
    delete_http_req(req);
}

struct http_200_cb_data {
    struct http_req* req;
    struct static_file_server* server;
    struct mapped_file* file;

    int res_hdrs_len;
    char res_hdrs[200];
};

static void http_200_response_headers_cb(void* data, struct tcp_conn* conn, int err) {
    struct http_200_cb_data* cb_data = (struct http_200_cb_data*)data;
    if (err != 0) {
        LOG_ERROR("Failed to write 200 response headers to request %s %s from connection %s:%d errno=%d (%s)",
                  cb_data->req->method, cb_data->req->path, ipv4_str(conn->ipv4), conn->port, err, strerror(err));
        close_file(cb_data->server->cache, cb_data->file);
        delete_http_req(cb_data->req);
        free(cb_data);
    }
}

static void http_200_response_body_cb(void* data, struct tcp_conn* conn, int err) {
    struct http_200_cb_data* cb_data = (struct http_200_cb_data*)data;
    if (err != 0) {
        LOG_ERROR("Failed to write file response to request %s %s from connection %s:%d errno=%d (%s)",
                  cb_data->req->method, cb_data->req->path, ipv4_str(conn->ipv4), conn->port, errno, strerror(errno));
    } else {
        LOG_INFO("%s %s %s 200 OK", ipv4_str(conn->ipv4), cb_data->req->method, cb_data->req->path);
    }
    close_file(cb_data->server->cache, cb_data->file);
    delete_http_req(cb_data->req);
    free(cb_data);
}

static void serve_static_file(struct static_file_server* server, struct http_req* req) {
    struct mapped_file* file = find_file(server, req);
    if (file == 0) {
        write_queue_push(server->write_queue, req->conn, http_404_response, http_404_response_len, req,
                         http_404_write_cb);
        return;
    }

    const char* content_type_hdr_value = "application/octet-stream";
    for (int i = 0; i < NUM_KNOWN_EXTENSIONS; i++) {
        if (file->path_len >= known_extensions[i].ext_len &&
            strcmp(file->path + (file->path_len - known_extensions[i].ext_len), known_extensions[i].ext) == 0) {
            content_type_hdr_value = known_extensions[i].content_type;
            break;
        }
    }

    struct http_200_cb_data* cb_data = malloc(sizeof(struct http_200_cb_data));
    if (cb_data == 0) {
        LOG_ERROR("Failed to allocate callback data for writing response to request %s %s from connection %s:%d",
                  req->method, req->path, ipv4_str(req->conn->ipv4), req->conn->port);
        close_file(server->cache, file);
        delete_http_req(req);
        return;
    }
    cb_data->req = req;
    cb_data->server = server;
    cb_data->file = file;
    cb_data->res_hdrs_len = snprintf(cb_data->res_hdrs, 200,
                                    "HTTP/1.1 200 OK\r\n"
                                    "Server: NDC/1.0.0\r\n"
                                    "Content-Type: %s\r\n"
                                    "Content-Length: %d\r\n"
                                    "\r\n",
                                    content_type_hdr_value, file->content_len);
    if (cb_data->res_hdrs_len < 0) {
        LOG_ERROR("Failed to format response headers of request %s %s from connection %s:%d: snprintf returned %d",
                  req->method, req->path, ipv4_str(req->conn->ipv4), req->conn->port, cb_data->res_hdrs_len);
        free(cb_data);
        close_file(server->cache, file);
        delete_http_req(req);
        return;
    }
    write_queue_push(server->write_queue, req->conn, cb_data->res_hdrs, cb_data->res_hdrs_len, cb_data,
                     http_200_response_headers_cb);
    write_queue_push(server->write_queue, req->conn, file->content, file->content_len, cb_data,
                     http_200_response_body_cb);
}

void on_http_req_callback(void* cb_data, struct http_req* req) {
    serve_static_file((struct static_file_server*)cb_data, req);
}
