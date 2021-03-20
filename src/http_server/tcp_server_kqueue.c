#include <errno.h>
#include <sys/event.h>

#include "../logging/logging.h"
#include "tcp_server.h"

void run_tcp_server_loop(struct tcp_server *server) {
    struct kevent *events = (struct kevent *)server->r_loop.events;
    while (1) {
        int n_ev = kevent(server->r_loop.fd, 0, 0, events, server->r_loop.max_events, 0);
        if (n_ev < 0) {
            // TODO: Handle error better.
            LOG_FATAL("Server: kevent() failed errno=%d (%s)", errno, errno_str(errno));
        }

        if (n_ev == 0) {
            LOG_WARN("Server: Spurious wake-up from kevent()");
            continue;
        }

        int should_process_notification = 0;
        for (int i = 0; i < n_ev; i++) {
            int event_fd = (int)events[i].ident;
            if (event_fd == server->listen_fd) {
                LOG_DEBUG("Received kevent on TCP server socket (fd=%d)", server->listen_fd);
                accept_tcp_conn(server);
            } else if (event_fd == server->r_loop.notify_pipe[0]) {
                should_process_notification = 1;
            } else {
                struct tcp_conn *conn = (struct tcp_conn *)events[i].udata;
                if (events[i].flags & EV_EOF) {
                    close_tcp_conn_in_loop(conn);
                } else if (events[i].filter & EVFILT_READ) {
                    LOG_DEBUG("Received read kevent on connection %s:%d (fd=%d)", ipv4_str(conn->ipv4), conn->port,
                              conn->fd);
                    recv_from_tcp_conn(conn);
                } else {
                    LOG_ERROR("Received unexpected event from kevent() fd=%d, event.flags=%d, event.filter=%u",
                              event_fd, events[i].flags, events[i].filter);
                }
            }
        }
        if (should_process_notification) {
            // Process notifications last, because in case we close and free a connection because of
            // a notification, the pointer to the tcp_conn saved in the kevent() becomes a dangling
            // pointer.
            tcp_server_process_notification(server);
        }
    }
}
