#include "http.h"
#include "logging.h"
#include "static_file_server.h"
#include "tcp_conn_table.h"
#include "tcp_server.h"

int main() {
    init_logging(1, 0);
    struct tcp_conn_table* table = new_tcp_conn_table(23, 4, 1 << 16);
    if (table == 0) {
        LOG_FATAL("Failed to allocate memory for tcp connection table");
    }
    struct static_file_server* static_files = new_static_file_server("./");
    if (static_files == 0) {
        LOG_FATAL("Failed to allocate memory for static file server");
    }
    struct http_req_queue* http_req_queue = new_http_req_queue(static_files, 1 << 16, 4);
    if (http_req_queue == 0) {
        LOG_FATAL("Failed to allocate memory for HTTP requests queue");
    }
    int tcp_server_fd = init_tcp_server(1337, 16);
    if (tcp_server_fd < 0) {
        return 1;
    }
    run_tcp_server(http_req_queue, table, tcp_server_fd);
    return 0;
}
