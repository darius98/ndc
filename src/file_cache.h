#ifndef NDC_FILE_CACHE_H_
#define NDC_FILE_CACHE_H_

struct mapped_file {
    int ref_count;
    int fd;
    unsigned int key;
    int path_len;
    int content_len;
    char* path;
    void* content;
};

struct file_cache;

struct file_cache* new_file_cache(int n_buckets, int bucket_init_cap);

/// Note: Takes ownership of path.
struct mapped_file* open_file(struct file_cache* cache, char* path);

void close_file(struct file_cache* cache, struct mapped_file* file);

#endif
