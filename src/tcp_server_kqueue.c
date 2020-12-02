#include <errno.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/event.h>
#include <unistd.h>

#include "logging.h"
#include "tcp_server.h"

void run_tcp_server_loop(struct tcp_server *server) {
    int kqueue_fd = kqueue();
    if (kqueue_fd < 0) {
        LOG_FATAL("Failed to start TCP server: kqueue() failed errno=%d (%s)", errno, strerror(errno));
    }

    struct kevent event;
    EV_SET(&event, tcp_server_get_fd(server), EVFILT_READ, EV_ADD, 0, 0, 0);
    if (kevent(kqueue_fd, &event, 1, 0, 0, 0) < 0) {
        LOG_FATAL("Failed to start TCP server: kevent() failed errno=%d (%s)", errno, strerror(errno));
    }

    LOG_INFO("Running HTTP server on port %d", tcp_server_get_port(server));

    struct tcp_conn *conn;
    while (1) {
        int n_ev = kevent(kqueue_fd, 0, 0, &event, 1, 0);
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
        if (event_fd == tcp_server_get_fd(server)) {
            LOG_DEBUG("Received kevent on TCP server socket (fd=%d)", tcp_server_get_fd(server));
            conn = accept_tcp_conn(server);
            if (conn != 0) {
                EV_SET(&event, conn->fd, EVFILT_READ, EV_ADD, 0, 0, conn);
                if (kevent(kqueue_fd, &event, 1, 0, 0, 0) < 0) {
                    LOG_ERROR("Could not accept TCP connection from %s:%d (fd=%d), kevent() failed errno=%d (%s)",
                              ipv4_str(conn->ipv4), conn->port, conn->fd, errno, strerror(errno));
                    close_tcp_conn(server, conn);
                }
            }
        } else {
            conn = (struct tcp_conn *)event.udata;
            if (event.flags & EV_EOF) {
                if (atomic_load_explicit(&conn->is_closed, memory_order_acquire) == 0) {
                    LOG_DEBUG("Closing connection %s:%d (fd=%d) because of EOF kevent",
                              ipv4_str(conn->ipv4), conn->port, conn->fd);
                    close_tcp_conn(server, conn);
                }
            } else if (event.filter & EVFILT_READ) {
                LOG_DEBUG("Received read kevent on connection %s:%d (fd=%d)", ipv4_str(conn->ipv4), conn->port,
                          conn->fd);
                int n_bytes = recv_from_tcp_conn(server, conn);
                if (n_bytes <= 0) {
                    if (n_bytes == 0) {
                        LOG_WARN("Spurious wake-up of connection %s:%d (fd=%d), had no bytes to read",
                                 ipv4_str(conn->ipv4), conn->port, conn->fd);
                    } else {
                        LOG_ERROR("Closing TCP connection to %s:%d (fd=%d)", ipv4_str(conn->ipv4), conn->port,
                                  conn->fd);
                        close_tcp_conn(server, conn);
                    }
                }
            } else {
                LOG_ERROR("Received unexpected event from kevent() fd=%d, event.flags=%d, event.filter=%u", event_fd,
                          event.flags, event.filter);
            }
        }
    }
}
