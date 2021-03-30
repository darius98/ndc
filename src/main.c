#include <signal.h>

#include "conf/conf.h"
#include "http/handlers/static_files/file_cache.h"
#include "http/handlers/static_files/static_files_handler.h"
#include "http/server/http_server.h"
#include "logging/logging.h"

static int always_should_handle(UNUSED void* data, UNUSED struct http_req* req) {
    return 1;
}

static void run_ndc_application_sync(const struct conf* conf) {
    struct http_server http_server;
    init_http_server(&http_server, conf);

    struct file_cache file_cache;
    init_file_cache(&file_cache, &conf->file_cache);
    struct static_files_handler static_files_handler;
    init_static_file_server(&static_files_handler, &file_cache, "./");
    struct http_handler handler;
    handler.name = "static_files_handler";
    handler.data = &static_files_handler;
    handler.should_handle = always_should_handle;
    handler.handle = static_file_server_handle;
    install_http_handler(&http_server, handler);

    start_http_server(&http_server);
}

int main() {
    // Ignore sigpipe, since we handle broken pipe errors in code.
    signal(SIGPIPE, SIG_IGN);

    struct conf conf = load_conf();

    init_logging(&conf.logging);

    if (!conf.is_from_file) {
        LOG_INFO(
            "No conf file found at %s, using default settings. Use environment variable %s to point to a different "
            "conf file location instead.",
            conf.file_path, NDC_CONF_FILE_ENV_VAR);
    }

    run_ndc_application_sync(&conf);
    return 0;
}
