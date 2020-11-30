#include "http_server.h"
#include "logging.h"
#include "static_file_server.h"
#include "tcp_server.h"

int main() {
    init_logging(1, 0);
    struct static_file_server* static_file_server = new_static_file_server("./", 23, 4);
    struct http_server* http_server = new_http_server(65536, 1, static_file_server);
    struct tcp_server* tcp_server = new_tcp_server(1337, 2048, 23, 4, 65536, http_server);
    static_file_server_set_tcp_server(static_file_server, tcp_server);
    run_tcp_server_loop(tcp_server);
    return 0;
}
