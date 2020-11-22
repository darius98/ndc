#ifndef NDC_SERVE_FILE_H_
#define NDC_SERVE_FILE_H_

struct http_req;

struct static_file_server {
    int base_dir_len;
    char* base_dir;
};

struct static_file_server* new_static_file_server(const char* base_dir);

void serve_static_file(struct static_file_server* server, struct http_req* req);

#endif
