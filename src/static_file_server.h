#ifndef NDC_SERVE_FILE_H_
#define NDC_SERVE_FILE_H_

struct static_file_server {
    int base_dir_len;
    char* base_dir;
};

struct static_file_server* new_static_file_server(const char* base_dir);

#endif
