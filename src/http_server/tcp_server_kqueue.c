#include <errno.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <sys/event.h>

#include "../logging/logging.h"
#include "tcp_server.h"

void run_tcp_server_loop(struct tcp_server *server) {
    int kqueue_fd = kqueue();
    if (kqueue_fd < 0) {
        LOG_FATAL("Failed to start TCP server: kqueue() failed errno=%d (%s)", errno, errno_str(errno));
    }
    server->loop_fd = kqueue_fd;

    struct kevent event;
    EV_SET(&event, server->listen_fd, EVFILT_READ, EV_ADD, 0, 0, 0);
    if (kevent(kqueue_fd, &event, 1, 0, 0, 0) < 0) {
        LOG_FATAL("Failed to start TCP server: kevent() failed errno=%d (%s)", errno, errno_str(errno));
    }
    EV_SET(&event, server->notify_pipe[0], EVFILT_READ, EV_ADD, 0, 0, 0);
    if (kevent(kqueue_fd, &event, 1, 0, 0, 0) < 0) {
        LOG_FATAL("Failed to start TCP server: kevent() failed errno=%d (%s)", errno, errno_str(errno));
    }

    struct kevent *events = malloc(sizeof(struct kevent) * server->conf->events_batch_size);
    if (events == 0) {
        LOG_FATAL("Failed to start TCP server: failed to allocate %d kevents (malloc failed %zu bytes)",
                  server->conf->events_batch_size, sizeof(struct kevent) * server->conf->events_batch_size);
    }

    LOG_INFO("Running HTTP server on port %d", server->port);

    while (1) {
        int n_ev = kevent(kqueue_fd, 0, 0, events, server->conf->events_batch_size, 0);
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
                struct tcp_conn *conn = accept_tcp_conn(server);
                if (conn != 0) {
                    EV_SET(&event, conn->fd, EVFILT_READ, EV_ADD, 0, 0, conn);
                    if (kevent(kqueue_fd, &event, 1, 0, 0, 0) < 0) {
                        LOG_ERROR("Could not accept TCP connection from %s:%d (fd=%d), kevent() failed errno=%d (%s)",
                                  ipv4_str(conn->ipv4), conn->port, conn->fd, errno, errno_str(errno));
                        close_tcp_conn_in_loop(server, conn);
                    }
                }
            } else if (event_fd == server->notify_pipe[0]) {
                should_process_notification = 1;
            } else {
                struct tcp_conn *conn = (struct tcp_conn *)events[i].udata;
                if (events[i].flags & EV_EOF) {
                    close_tcp_conn_in_loop(server, conn);
                } else if (events[i].filter & EVFILT_READ) {
                    LOG_DEBUG("Received read kevent on connection %s:%d (fd=%d)", ipv4_str(conn->ipv4), conn->port,
                              conn->fd);
                    recv_from_tcp_conn(server, conn);
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

void remove_conn_from_read_loop(struct tcp_server *server, struct tcp_conn *conn) {
    struct kevent event;
    EV_SET(&event, conn->fd, EVFILT_READ, EV_DELETE, 0, 0, conn);
    if (kevent(server->loop_fd, &event, 1, 0, 0, 0) < 0) {
        LOG_ERROR("Could not remove TCP connection %s:%d (fd=%d) from read loop, kevent() failed errno=%d (%s)",
                  ipv4_str(conn->ipv4), conn->port, conn->fd, errno, errno_str(errno));
    } else {
        LOG_DEBUG("Removed connection %s:%d (fd=%d) from read loop", ipv4_str(conn->ipv4), conn->port, conn->fd);
    }
}
