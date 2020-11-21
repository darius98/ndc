#ifndef NDC_TCP_SERVER_H_
#define NDC_TCP_SERVER_H_

#include "http.h"
#include "tcp_conn_table.h"

void run_tcp_server(struct http_req_queue* req_queue, struct tcp_conn_table* conn_table, int port, int max_clients);

#endif
