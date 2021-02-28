#include <errno.h>
#include <stdlib.h>
#include <sys/epoll.h>

#include "../logging/logging.h"
#include "tcp_server.h"

void run_tcp_server_loop(struct tcp_server *server) {
    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        LOG_FATAL("Failed to start server: epoll_create1() failed errno=%d (%s)", errno, errno_str(errno));
    }
    server->loop_fd = epoll_fd;

    struct epoll_event event;
    event.events = EPOLLIN;
    event.data.ptr = &server->listen_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server->listen_fd, &event) < 0) {
        LOG_FATAL("Failed to start server: epoll_ctl() failed errno=%d (%s)", errno, errno_str(errno));
    }
    event.events = EPOLLIN;
    event.data.ptr = &server->notify_pipe[0];
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server->notify_pipe[0], &event) < 0) {
        LOG_FATAL("Failed to start server: epoll_ctl() failed errno=%d (%s)", errno, errno_str(errno));
    }

    int num_events = server->conf->events_batch_size;
    struct epoll_event *events = malloc(sizeof(struct epoll_event) * num_events);
    if (events == 0) {
        LOG_FATAL("Failed to start TCP server: failed to allocate %d epoll_events (malloc failed %zu bytes)",
                  num_events, sizeof(struct epoll_event) * num_events);
    }

    LOG_INFO("Running HTTP server on port %d", server->port);

    struct tcp_conn *conn;
    while (1) {
        int n_ev = epoll_wait(epoll_fd, events, num_events, -1);
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
                conn = accept_tcp_conn(server);
                if (conn != 0) {
                    event.events = EPOLLIN;  // TODO: | EPOLLET;
                    event.data.ptr = conn;
                    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, conn->fd, &event) < 0) {
                        LOG_ERROR(
                            "Could not accept TCP connection from %s:%d (fd=%d), epoll_ctl() failed errno=%d (%s)",
                            ipv4_str(conn->ipv4), conn->port, conn->fd, errno, errno_str(errno));
                        close_tcp_conn_in_loop(conn);
                    }
                }
            } else if (events[i].data.ptr == &server->notify_pipe[0]) {
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

void remove_conn_from_read_loop(struct tcp_conn *conn) {
    struct epoll_event event;
    event.events = EPOLLIN;  // TODO: | EPOLLET;
    event.data.ptr = conn;
    if (epoll_ctl(conn->server->loop_fd, EPOLL_CTL_DEL, conn->fd, &event) < 0) {
        LOG_ERROR("Could not remove TCP connection %s:%d (fd=%d) from read loop, epoll_ctl() failed errno=%d (%s)",
                  ipv4_str(conn->ipv4), conn->port, conn->fd, errno, errno_str(errno));
    }
}
