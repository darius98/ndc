#ifndef NDC_FILE_CACHE_H_
#define NDC_FILE_CACHE_H_

#include "conf.h"
#include "ff_pthread.h"

struct mapped_file {
    int ref_count;
    int fd;
    unsigned int key;
    int path_len;
    int content_len;
    char* path;
    void* content;
};

struct file_cache_bucket {
    int size;
    int cap;
    struct mapped_file** entries;
};

struct file_cache {
    int size;
    int n_buckets;
    struct file_cache_bucket* buckets;
    pthread_mutex_t lock;
};

/// Initialize a new file cache. Note: Aborts on failure.
void init_file_cache(struct file_cache* cache, const struct file_cache_conf* conf);

/// Note: Takes ownership of path.
struct mapped_file* open_file(struct file_cache* cache, char* path);

void close_file(struct file_cache* cache, struct mapped_file* file);

#endif
