#ifndef NDC_SERVE_FILE_H_
#define NDC_SERVE_FILE_H_

struct static_file_server;

/// Allocate and initialize a static file server.
/// Note: Aborts on failure.
struct static_file_server* new_static_file_server(const char* base_dir, int fcache_n_buckets,
                                                  int fcache_bucket_init_cap);

#endif
