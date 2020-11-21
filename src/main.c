#include "http.h"
#include "logging.h"
#include "tcp_conn_table.h"
#include "tcp_server.h"

int main() {
    init_logging(1, 0);
    struct tcp_conn_table* table = new_tcp_conn_table(23, 4, 1 << 16);
    if (table == 0) {
        LOG_FATAL("Failed to allocate memory for tcp connection table");
    }
    struct http_req_queue* req_queue = new_http_req_queue(1 << 16, 4);
    if (req_queue == 0) {
        LOG_FATAL("Failed to allocate memory for HTTP requests queue");
    }
    run_tcp_server(req_queue, table, 1337, 16);
}
