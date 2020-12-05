#include <signal.h>

#include "conf.h"
#include "file_cache.h"
#include "http_server.h"
#include "logging.h"
#include "static_file_server.h"
#include "tcp_server.h"

int main() {
    // Ignore sigpipe, since we handle broken pipe errors in code.
    signal(SIGPIPE, SIG_IGN);

    struct conf conf = load_conf();

    init_logging(&conf.logging);

    if (!conf.is_from_file) {
        LOG_WARN(
            "No conf file found at %s, using default settings. Use environment variable %s to point to a different "
            "conf file location instead.",
            conf.file_path, NDC_CONF_FILE_ENV_VAR);
    }

    struct file_cache file_cache;
    init_file_cache(&file_cache, &conf.file_cache);

    struct tcp_server tcp_server;
    init_tcp_server(&tcp_server, 1337, &conf.tcp_server, &conf.tcp_write_queue);

    struct http_server http_server;
    init_http_server(&http_server, &conf.http);
    tcp_server.cb_data = &http_server;

    struct static_file_server static_file_server;
    init_static_file_server(&static_file_server, &file_cache, &tcp_server, "./");
    http_server.cb_data = &static_file_server;

    run_tcp_server_loop(&tcp_server);
    return 0;
}
