#include "app.h"

#include "http_handlers/static_files/file_cache.h"
#include "http_handlers/static_files/static_file_server.h"
#include "http_server/http_server.h"

int always_should_handle(void* data, struct http_req* req) {
    return 1;
}

void run_ndc_application_sync(const struct conf* conf) {
    struct http_server http_server;
    init_http_server(&http_server, conf);

    struct file_cache file_cache;
    init_file_cache(&file_cache, &conf->file_cache);
    struct static_file_server static_file_server;
    init_static_file_server(&static_file_server, &file_cache, &http_server, "./");
    struct http_handler handler;
    handler.name = "static_file_server";
    handler.data = &static_file_server;
    handler.should_handle = always_should_handle;
    handler.handle = static_file_server_handle;
    install_http_handler(&http_server, handler);

    start_http_server(&http_server);
}
