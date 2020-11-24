#include "http.h"
#include "logging.h"
#include "static_file_server.h"
#include "tcp_server.h"
#include "tcp_server_loop.h"

int main() {
    init_logging(1, 0);
    struct static_file_server* static_files = new_static_file_server("./");
    if (static_files == 0) {
        LOG_FATAL("Failed to allocate memory for static file server");
    }
    struct http_req_queue* http_req_queue = new_http_req_queue(static_files, 1 << 16, 4);
    if (http_req_queue == 0) {
        LOG_FATAL("Failed to allocate memory for HTTP requests queue");
    }
    struct tcp_server* server = init_tcp_server(http_req_queue, 1337, 2048, 23, 4, 1 << 16);
    if (server == 0) {
        return 1;
    }
    run_tcp_server_loop(server);
    return 0;
}
