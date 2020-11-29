#include "file_cache.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "logging.h"

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

struct file_cache* new_file_cache(int n_buckets, int bucket_init_cap) {
    struct file_cache* cache = malloc(sizeof(struct file_cache));
    if (cache == 0) {
        return 0;
    }
    ASSERT_0(pthread_mutex_init(&cache->lock, 0));
    cache->size = 0;
    cache->n_buckets = n_buckets;
    cache->buckets = malloc(sizeof(struct file_cache_bucket) * n_buckets);
    if (cache->buckets == 0) {
        free(cache);
        return 0;
    }
    for (int i = 0; i < cache->n_buckets; i++) {
        cache->buckets[i].size = 0;
        cache->buckets[i].cap = bucket_init_cap;
        cache->buckets[i].entries = malloc(sizeof(void*) * cache->buckets[i].cap);
        if (cache->buckets[i].entries == 0) {
            for (int j = 0; j < i; j++) {
                free(cache->buckets[j].entries);
            }
            free(cache->buckets);
            free(cache);
            return 0;
        }
    }
    return cache;
}

static unsigned int make_hash_key(const char* path, int path_len) {
    unsigned int hash = 0;
    for (int i = 0; i < path_len; ++i) {
        hash += path[i];
        hash += (hash << 10u);
        hash ^= (hash >> 6u);
    }
    hash += (hash << 3u);
    hash ^= (hash >> 11u);
    hash += (hash << 15u);
    return hash;
}

static int file_cache_insert(struct file_cache* cache, struct mapped_file* file) {
    struct file_cache_bucket* bucket = &cache->buckets[file->key % cache->n_buckets];
    if (bucket->size == bucket->cap) {
        void* resized = realloc(bucket->entries, sizeof(void*) * bucket->cap * 2);
        if (resized == 0) {
            return -1;
        }
        bucket->entries = resized;
        bucket->cap *= 2;
    }
    bucket->entries[bucket->size++] = file;
    cache->size++;
    return 0;
}

static int file_cache_erase(struct file_cache* cache, struct mapped_file* file) {
    struct file_cache_bucket* bucket = &cache->buckets[file->key % cache->n_buckets];
    for (int i = 0; i < bucket->size; i++) {
        if (bucket->entries[i] == file) {
            bucket->entries[i] = bucket->entries[bucket->size - 1];
            bucket->size -= 1;
            cache->size -= 1;
            return 0;
        }
    }
    return -1;
}

static struct mapped_file* file_cache_lookup(struct file_cache* cache, const char* path) {
    unsigned int key = make_hash_key(path, strlen(path));
    struct file_cache_bucket* bucket = &cache->buckets[key % cache->n_buckets];
    for (int i = 0; i < bucket->size; i++) {
        if (bucket->entries[i]->key == key && strcmp(bucket->entries[i]->path, path) == 0) {
            return bucket->entries[i];
        }
    }
    return 0;
}

static struct mapped_file* map_file(char* path) {
    struct mapped_file* file = malloc(sizeof(struct mapped_file));
    if (file == 0) {
        LOG_ERROR("Failed to open file %s: malloc() failed", path);
        free(path);
        return 0;
    }

    file->ref_count = 1;
    file->path_len = strlen(path);
    file->path = path;
    file->key = make_hash_key(file->path, file->path_len);

    file->fd = open(path, O_RDONLY);
    if (file->fd < 0) {
        LOG_ERROR("Failed to open file %s: open() failed errno=%d (%s)", path, errno, strerror(errno));
        free(file->path);
        free(file);
        return 0;
    }

    struct stat file_stat;
    if (fstat(file->fd, &file_stat) < 0) {
        LOG_ERROR("Failed to open file %s: fstat() failed errno=%d (%s)", path, errno, strerror(errno));
        if (close(file->fd) < 0) {
            LOG_ERROR("Failed to close file %s: close() failed errno=%d (%s)", path, errno, strerror(errno));
        }
        free(file->path);
        free(file);
        return 0;
    }

    file->content_len = file_stat.st_size;
    file->content = mmap(0, file->content_len, PROT_READ, MAP_PRIVATE, file->fd, 0);
    if (file->content == MAP_FAILED) {
        LOG_ERROR("Failed to open file %s: mmap() failed errno=%d (%s)", path, errno, strerror(errno));
        if (close(file->fd) < 0) {
            LOG_ERROR("Failed to close file %s: close() failed errno=%d (%s)", path, errno, strerror(errno));
        }
        free(file->path);
        free(file);
        return 0;
    }
    return file;
}

void unmap_file(struct mapped_file* file) {
    if (close(file->fd) < 0) {
        LOG_ERROR("Error closing file %s: close() failed errno=%d (%s)", file->path, errno, strerror(errno));
    }
    if (munmap(file->content, file->content_len) < 0) {
        LOG_ERROR("Error closing file %s: munmap() failed errno=%d (%s)", file->path, errno, strerror(errno));
    }
    free(file->path);
}

struct mapped_file* open_file(struct file_cache* cache, char* path) {
    ASSERT_0(pthread_mutex_lock(&cache->lock));
    struct mapped_file* file = file_cache_lookup(cache, path);
    if (file == 0) {
        file = map_file(path);
        if (file == 0) {
            ASSERT_0(pthread_mutex_unlock(&cache->lock));
            return 0;
        }
        if (file_cache_insert(cache, file) < 0) {
            unmap_file(file);
            return 0;
        }
    } else {
        file->ref_count += 1;
        free(path);
    }
    ASSERT_0(pthread_mutex_unlock(&cache->lock));
    return file;
}

void close_file(struct file_cache* cache, struct mapped_file* file) {
    int unmap = 0;
    ASSERT_0(pthread_mutex_lock(&cache->lock));
    if ((--file->ref_count) == 0) {
        file_cache_erase(cache, file);
        unmap = 1;
    }
    ASSERT_0(pthread_mutex_unlock(&cache->lock));
    if (unmap == 1) {
        unmap_file(file);
    }
}
