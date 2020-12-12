#include "app.h"

#include "file_cache.h"
#include "http_server.h"
#include "static_file_server.h"
#include "tcp_server.h"

void run_ndc_application_sync(const struct conf* conf) {
    struct file_cache file_cache;
    init_file_cache(&file_cache, &conf->file_cache);

    struct tcp_server tcp_server;
    init_tcp_server(&tcp_server, 1337, &conf->tcp_server, &conf->tcp_write_queue);

    struct http_server http_server;
    init_http_server(&http_server, &conf->http);
    tcp_server.cb_data = &http_server;

    struct static_file_server static_file_server;
    init_static_file_server(&static_file_server, &file_cache, &tcp_server, "./");
    http_server.cb_data = &static_file_server;

    run_tcp_server_loop(&tcp_server);
}
