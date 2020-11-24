#ifndef NDC_TCP_SERVER_LOOP_H_
#define NDC_TCP_SERVER_LOOP_H_

#include "http.h"
#include "tcp_conn_table.h"

void run_tcp_server_loop(struct tcp_server *server);

#endif
