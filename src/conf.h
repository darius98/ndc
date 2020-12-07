#ifndef NDC_CONF_H_
#define NDC_CONF_H_

#define NDC_CONF_FILE_ENV_VAR "NDC_CONF_FILE"

struct logging_conf {
    const char* access_log;
    const char* server_log;
    int min_level;
    int filename_and_lineno;
};

struct file_cache_conf {
    int num_buckets;
    int bucket_initial_capacity;
};

struct tcp_server_conf {
    int backlog;
    int num_buckets;
    int bucket_initial_capacity;
    int events_batch_size;
    int connection_buffer_size;
};

struct tcp_write_queue_conf {
    int num_buckets;
    int bucket_initial_capacity;
    int events_batch_size;
};

struct http_conf {
    int num_workers;
    int request_buffer_size;
};

struct conf {
    int is_from_file;
    const char* file_path;
    struct logging_conf logging;
    struct file_cache_conf file_cache;
    struct tcp_server_conf tcp_server;
    struct tcp_write_queue_conf tcp_write_queue;
    struct http_conf http;
};

struct conf load_conf();

#endif
