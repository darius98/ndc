#include "static_file_server.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "http_server.h"
#include "logging.h"
#include "tcp_server.h"

// TODO: Rewrite everything.

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

struct static_file_server* new_static_file_server(const char* base_dir) {
    struct static_file_server* server = malloc(sizeof(struct static_file_server));
    if (server == 0) {
        LOG_FATAL("Failed to allocate memory for static file server");
    }
    server->base_dir_len = strlen(base_dir);
    server->base_dir = malloc(server->base_dir_len + 1);
    if (server->base_dir == 0) {
        LOG_FATAL("Failed to allocate memory for static file server base_dir string.");
    }
    strcpy(server->base_dir, base_dir);
    return server;
}

static int sync_write(int fd, const char* buf, int buf_len) {
    int written_sz = 0;
    while (written_sz < buf_len) {
        ssize_t chunk_sz = write(fd, buf + written_sz, buf_len - written_sz);
        if (chunk_sz < 0) {
            return chunk_sz;
        }
        written_sz += chunk_sz;
    }
    return written_sz;
}

static int sync_write_file(int fd, FILE* file) {
    char buf[4096];
    while (1) {
        size_t len = fread(buf, 1, 4096, file);
        if (len == 0 && ferror(file) != 0) {
            return -1;
        }
        if (sync_write(fd, buf, len) < 0) {
            return -2;
        }
        if (len < 4096) {
            return 0;
        }
    }
}

static void serve_static_file(struct static_file_server* server, struct http_req* req) {
    int req_path_len = strlen(req->path);
    char* path = malloc(server->base_dir_len + req_path_len + 1);
    if (path == 0) {
        LOG_ERROR("Failed to allocate memory while responding to HTTP request %s:%d %s %s", ipv4_str(req->conn->ipv4),
                  req->conn->port, req->method, req->path);
        return;
    }
    path[0] = 0;
    strcat(path, server->base_dir);
    int skip_first_slash = path[server->base_dir_len - 1] == '/' && req->path[0] == '/' ? 1 : 0;
    strcat(path, req->path + skip_first_slash);
    FILE* file = fopen(path, "rb");
    if (file == 0) {
        if (sync_write(req->conn->fd, http_404_response, http_404_response_len) < 0) {
            LOG_ERROR("Failed to write 404 Not found response to request %s %s from connection %s:%d errno=%d (%s)",
                      req->method, req->path, ipv4_str(req->conn->ipv4), req->conn->port, errno, strerror(errno));
        } else {
            LOG_INFO("%s %s %s 404 Not found", ipv4_str(req->conn->ipv4), req->method, req->path);
        }
        free(path);
        return;
    }
    int path_len = server->base_dir_len + req_path_len - skip_first_slash;
    const char* content_type_hdr_value = "application/octet-stream";
    for (int i = 0; i < NUM_KNOWN_EXTENSIONS; i++) {
        if (path_len >= known_extensions[i].ext_len &&
            strcmp(path + (path_len - known_extensions[i].ext_len), known_extensions[i].ext) == 0) {
            content_type_hdr_value = known_extensions[i].content_type;
            break;
        }
    }
    fseek(file, 0L, SEEK_END);
    long content_len = ftell(file);
    fseek(file, 0L, SEEK_SET);
    char response_hdr[200];
    int response_hdr_len = snprintf(response_hdr, 200,
                                    "HTTP/1.1 200 OK\r\n"
                                    "Server: NDC/1.0.0\r\n"
                                    "Content-Type: %s\r\n"
                                    "Content-Length: %ld\r\n"
                                    "\r\n",
                                    content_type_hdr_value, content_len);
    if (response_hdr_len < 0) {
        LOG_ERROR("snprintf failed error=%d", response_hdr_len);
        free(path);
        fclose(file);
        return;
    }
    if (sync_write(req->conn->fd, response_hdr, response_hdr_len) < 0) {
        LOG_ERROR("Failed to write 200 response headers to request %s %s from connection %s:%d errno=%d (%s)",
                  req->method, req->path, ipv4_str(req->conn->ipv4), req->conn->port, errno, strerror(errno));
        free(path);
        fclose(file);
        return;
    }
    int err = sync_write_file(req->conn->fd, file) < 0;
    if (err < 0) {
        LOG_ERROR("Failed to write file response to request %s %s from connection %s:%d errno=%d (%s)", req->method,
                  req->path, ipv4_str(req->conn->ipv4), req->conn->port, err == -1 ? ferror(file) : errno,
                  strerror(err == -1 ? ferror(file) : errno));
    } else {
        LOG_INFO("%s %s %s 200 OK", ipv4_str(req->conn->ipv4), req->method, req->path);
    }
    free(path);
    fclose(file);
}

void on_http_req_callback(void* cb_data, struct http_req* req) {
    serve_static_file((struct static_file_server*)cb_data, req);
    delete_http_req(req);
}
