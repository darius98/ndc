#ifndef NDC_HTTP_HANDLERS_STATIC_FILES_STATIC_FILES_HANDLER_H_
#define NDC_HTTP_HANDLERS_STATIC_FILES_STATIC_FILES_HANDLER_H_

struct file_cache;
struct http_server;
struct http_req;

struct static_files_handler {
    int base_dir_len;
    char* base_dir;

    struct file_cache* cache;
};

/// Initialize a static file server. Note: Aborts on failure.
void init_static_file_server(struct static_files_handler* server, struct file_cache* cache, const char* base_dir);

void static_file_server_handle(void* data, struct http_req* req);

#endif
