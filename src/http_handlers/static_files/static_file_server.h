#ifndef NDC_SERVE_FILE_H_
#define NDC_SERVE_FILE_H_

struct file_cache;
struct tcp_server;
struct http_server;

struct static_file_server {
    int base_dir_len;
    char* base_dir;

    struct file_cache* cache;
    struct tcp_server* tcp_server;
    struct http_server* http_server;
};

/// Initialize a static file server. Note: Aborts on failure.
void init_static_file_server(struct static_file_server* server, struct file_cache* cache, struct tcp_server* tcp_server,
                             struct http_server* http_server, const char* base_dir);

#endif
