#include "tcp_server_loop.h"

#include <errno.h>
#include <string.h>
#include <sys/event.h>

#include "logging.h"

void run_tcp_server_loop(struct tcp_server *server) {
    int kqueue_id = kqueue();
    if (kqueue_id < 0) {
        LOG_FATAL("Failed to start server: kqueue() failed errno=%d (%s)", errno, strerror(errno));
    }

    struct kevent event;
    EV_SET(&event, server->listen_fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, 0);
    if (kevent(kqueue_id, &event, 1, 0, 0, 0) < 0 && errno != EINTR) {
        LOG_FATAL("Failed to start server: kevent() failed errno=%d (%s)", errno, strerror(errno));
    }

    LOG_INFO("Running HTTP server on port %d", server->port);

    struct tcp_conn *conn;
    while (1) {
        int n_ev = kevent(kqueue_id, NULL, 0, &event, 1, NULL);
        if (n_ev < 0) {
            // TODO: Handle error better.
            LOG_FATAL("Server: kevent() failed errno=%d (%s)", errno, strerror(errno));
        }

        if (n_ev == 0) {
            LOG_WARN("Server: Spurious wake-up from kevent()");
            continue;
        }

        if (n_ev != 1) {
            LOG_ERROR("Server: kevent() returned %d events when capacity was 1.", n_ev);
        }
        int event_fd = (int)event.ident;
        if (event_fd == server->listen_fd) {
            LOG_DEBUG("Received kevent on TCP server socket (fd=%d)", server->listen_fd);
            conn = accept_tcp_conn(server);
            if (conn != 0) {
                EV_SET(&event, conn->fd, EVFILT_READ, EV_ADD, 0, 0, 0);
                if (kevent(kqueue_id, &event, 1, 0, 0, 0) < 0 && errno != EINTR) {
                    LOG_ERROR("Could not accept TCP connection from %s:%d (fd=%d), kevent() failed errno=%d (%s)",
                              ipv4_str(conn->ipv4), conn->port, conn->fd, errno, strerror(errno));
                    close_tcp_conn(server, conn);
                }
            }
        } else {
            conn = find_tcp_conn(server, event_fd);
            if (conn == 0) {
                LOG_WARN("Received kevent() on fd=%d, but could not find connection", event_fd);
            } else {
                LOG_DEBUG("Received kevent on connection %s:%d (fd=%d)", ipv4_str(conn->ipv4), conn->port, conn->fd);
                if (event.flags & EV_EOF) {
                    close_tcp_conn(server, conn);
                } else if (event.filter & EVFILT_READ) {
                    recv_from_tcp_conn(server, conn);
                } else {
                    LOG_ERROR("Received unexpected event from kevent() fd=%d, event.flags=%d, event.filter=%u",
                              event_fd, event.flags, event.filter);
                }
            }
        }
    }
}
