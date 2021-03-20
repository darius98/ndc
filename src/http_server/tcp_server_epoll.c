#include <errno.h>
#include <stdlib.h>
#include <sys/epoll.h>

#include "../logging/logging.h"
#include "tcp_server.h"

void run_tcp_server_loop(struct tcp_server *server) {
    struct epoll_event *events = (struct epoll_event *)server->r_loop.events;
    struct tcp_conn *conn;
    while (1) {
        int n_ev = epoll_wait(server->r_loop.fd, events, server->r_loop.max_events, -1);
        if (n_ev < 0) {
            // TODO: Handle error better.
            LOG_FATAL("Server: epoll_wait() failed errno=%d (%s)", errno, errno_str(errno));
        }

        if (n_ev == 0) {
            LOG_WARN("Server: Spurious wake-up from epoll_wait()");
            continue;
        }

        int should_process_notification = 0;
        for (int i = 0; i < n_ev; i++) {
            if ((events[i].events & EPOLLIN) == 0) {
                continue;  // TODO: Do something with EPOLLRDHUP
            }
            if (events[i].data.ptr == &server->listen_fd) {
                LOG_DEBUG("Received epoll event on TCP server socket (fd=%d)", server->listen_fd);
                accept_tcp_conn(server);
            } else if (events[i].data.ptr == &server->r_loop.notify_pipe[0]) {
                should_process_notification = 1;
            } else {
                conn = (struct tcp_conn *)events[i].data.ptr;
                LOG_DEBUG("Received epoll event on connection %s:%d (fd=%d)", ipv4_str(conn->ipv4), conn->port,
                          conn->fd);
                recv_from_tcp_conn(conn);
            }
        }
        if (should_process_notification) {
            tcp_server_process_notification(server);
        }
    }
}
