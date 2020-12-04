#include <errno.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

#include "logging.h"
#include "tcp_server.h"

void run_tcp_server_loop(struct tcp_server *server) {
    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        LOG_FATAL("Failed to start server: epoll_create1() failed errno=%d (%s)", errno, strerror(errno));
    }

    struct epoll_event event;
    event.events = EPOLLIN;
    event.data.fd = server->listen_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server->listen_fd, &event) < 0) {
        LOG_FATAL("Failed to start server: epoll_ctl() failed errno=%d (%s)", errno, strerror(errno));
    }
    event.events = EPOLLIN;
    event.data.fd = server->notify_pipe[0];
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server->notify_pipe[0], &event) < 0) {
        LOG_FATAL("Failed to start server: epoll_ctl() failed errno=%d (%s)", errno, strerror(errno));
    }

    LOG_INFO("Running HTTP server on port %d", server->port);

    struct tcp_conn *conn;
    while (1) {
        int n_ev = epoll_wait(epoll_fd, &event, 1, -1);
        if (n_ev < 0) {
            // TODO: Handle error better.
            LOG_FATAL("Server: epoll_wait() failed errno=%d (%s)", errno, strerror(errno));
        }

        if (n_ev == 0) {
            LOG_WARN("Server: Spurious wake-up from epoll_wait()");
            continue;
        }

        if (n_ev != 1) {
            LOG_ERROR("Server: epoll_wait() returned %d events when capacity was 1.", n_ev);
        }
        int event_fd = (int)event.data.fd;
        if (event_fd == server->listen_fd) {
            LOG_DEBUG("Received epoll event on TCP server socket (fd=%d)", server->listen_fd);
            conn = accept_tcp_conn(server);
            if (conn != 0) {
                event.events = EPOLLIN | EPOLLET;
                event.data.fd = conn->fd;
                if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, conn->fd, &event) < 0) {
                    LOG_ERROR("Could not accept TCP connection from %s:%d (fd=%d), epoll_ctl() failed errno=%d (%s)",
                              ipv4_str(conn->ipv4), conn->port, conn->fd, errno, strerror(errno));
                    close_tcp_conn(server, conn);
                }
            }
        } else if (event_fd == server->notify_pipe[0]) {
            tcp_server_process_notification(server);
        } else {
            conn = find_tcp_conn(server, event_fd);
            if (conn == 0) {
                LOG_WARN("Received epoll event on fd=%d, but could not find connection", event_fd);
            } else {
                LOG_DEBUG("Received epoll event on connection %s:%d (fd=%d)", ipv4_str(conn->ipv4), conn->port,
                          conn->fd);
                int n_bytes = recv_from_tcp_conn(server, conn);
                if (n_bytes <= 0) {
                    if (n_bytes < 0) {
                        LOG_ERROR("Closing TCP connection to %s:%d (fd=%d)", ipv4_str(conn->ipv4), conn->port,
                                  conn->fd);
                    }
                    close_tcp_conn(server, conn);
                }
            }
        }
    }
}
