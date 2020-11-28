#include "http_server.h"
#include "logging.h"
#include "static_file_server.h"
#include "tcp_server.h"

int main() {
    init_logging(1, 0);
    struct static_file_server* static_file_server = new_static_file_server("./");
    struct http_server* http_server = new_http_server(1 << 16, 4, static_file_server);
    struct tcp_server* tcp_server = new_tcp_server(1337, 2048, 23, 4, 1 << 16, http_server);
    run_tcp_server_loop(tcp_server);
    return 0;
}
