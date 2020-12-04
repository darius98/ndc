#include "file_cache.h"
#include "http_server.h"
#include "logging.h"
#include "static_file_server.h"
#include "tcp_server.h"

#include <signal.h>

int main() {
    // Ignore sigpipe, since we handle broken pipe errors in code.
    signal(SIGPIPE, SIG_IGN);

    init_logging(1, 0);

    struct file_cache file_cache;
    init_file_cache(&file_cache, 23, 4);

    struct tcp_server tcp_server;
    init_tcp_server(&tcp_server, 1337, 2048, 23, 4, 65536);

    struct http_server http_server;
    init_http_server(&http_server, 65536, 1);
    tcp_server.cb_data = &http_server;

    struct static_file_server static_file_server;
    init_static_file_server(&static_file_server, &file_cache, &tcp_server, "./");
    http_server.cb_data = &static_file_server;

    run_tcp_server_loop(&tcp_server);
    return 0;
}
