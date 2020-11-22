#ifndef NDC_HTTP_H_
#define NDC_HTTP_H_

#include <netinet/in.h>

struct static_file_server;

struct http_req {
    /// Source IP address of the request.
    char ip[INET_ADDRSTRLEN];

    /// Source port of the request.
    int port;

    /// A file descriptor where to stream the response.
    /// This is a duplicate file descriptor from the original TCP socket. It must be closed after
    /// the response to the HTTP request is streamed.
    int response_fd;

    /// Used length of the request buffer.
    int buf_len;

    /// Maximum length of the request buffer.
    int buf_cap;

    /// The bytes of a HTTP request.
    /// The request is copied into this string. The memory here is owned by the request handler and
    /// must be freed after the the response is streamed.
    char* buf;

    /// Null-terminated string pointing to the method of the request, inside the buffer.
    char* method;

    /// Null-terminated string pointing to the path of the request, inside the buffer.
    char* path;

    /// Null-terminated string pointing to the HTTP version of the request, inside the buffer.
    char* version;

    /// Null-terminated string pointing to the first HTTP header of the request, inside the buffer.
    char* headers;

    /// Parsed value of the Content-Length header (-1 if the header is not available or invalid).
    int body_len;

    /// Pointer to the body of the request. NOT null-terminated.
    char* body;

    /// For the queue of http requests.
    struct http_req* next;
};

struct http_req_queue;

/// Allocate and initialize a http requests queue.
/// Note: returns NULL on allocation failure.
struct http_req_queue* new_http_req_queue(struct static_file_server* static_files, int req_buf_cap, int num_workers);

/// Read all available HTTP requests from the start of the connection's buffer.
/// Returns the number of bytes parsed from buf.
int read_http_reqs(struct http_req_queue* req_queue, struct http_req** cur_req, char* buf, int tcp_conn_fd, char* ip, int port);

void delete_http_req(struct http_req_queue* req_queue, struct http_req* req);

#endif
