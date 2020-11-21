#include "tcp_server.h"

#include <arpa/inet.h>
#include <errno.h>
#include <memory.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/event.h>
#include <unistd.h>

#include "logging.h"

static int create_server_socket(int port, int max_clients) {
    int listen_fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_fd < 0) {
        LOG_FATAL("socket() failed errno=%d (%s)", errno, strerror(errno));
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(struct sockaddr_in));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(port);
    if (bind(listen_fd, (const struct sockaddr *)&server_addr, sizeof(struct sockaddr_in)) < 0) {
        LOG_FATAL("bind() failed errno=%d (%s)", errno, strerror(errno));
    }
    if (listen(listen_fd, max_clients) < 0) {
        LOG_FATAL("listen() failed errno=%d (%s)", errno, strerror(errno));
    }
    return listen_fd;
}

static struct tcp_conn *accept_conn(struct tcp_conn_table *conn_table, int listen_fd) {
    int fd;
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(struct sockaddr_in);
    fd = accept(listen_fd, (struct sockaddr *)&client_addr, &client_addr_len);
    if (fd < 0) {
        // TODO: Handle error better.
        LOG_FATAL("accept() failed errno=%d (%s)", errno, strerror(errno));
    }

    char ip[INET_ADDRSTRLEN + 1];
    inet_ntop(AF_INET, &client_addr.sin_addr, ip, INET_ADDRSTRLEN + 1);

    struct tcp_conn *conn = new_tcp_conn(conn_table, fd, ip, client_addr.sin_port);
    if (conn == 0) {
        // Errors are logged in new_tcp_conn.
        if (close(fd) < 0) {
            LOG_ERROR("Failed to close file descriptor %d for connection %s:%d, errno=%d (%s)", fd, ip,
                      client_addr.sin_port, errno, strerror(errno));
        }
        return 0;
    }
    LOG_DEBUG("TCP client connected: %s:%d (fd=%d)", conn->ip, conn->port, conn->fd);
    return conn;
}

static void close_conn(struct http_req_queue *req_queue, struct tcp_conn_table *conn_table, struct tcp_conn *conn) {
    if (close(conn->fd) < 0) {
        LOG_ERROR("Failed to close file descriptor %d for connection %s:%d, errno=%d (%s)", conn->fd, conn->ip,
                  conn->port, errno, strerror(errno));
    }
    if (conn->cur_req != 0) {
        delete_http_req(req_queue, conn->cur_req);
    }
    if (delete_tcp_conn(conn_table, conn) < 0) {
        LOG_ERROR(
            "close_conn(): connection %s:%d (fd=%d) is not in connections table. Memory for this "
            "connection will not be reclaimed, so this message may indicate a memory leak.",
            conn->ip, conn->port, conn->fd);
    }
    LOG_DEBUG("TCP client disconnected: %s:%d (fd=%d)", conn->ip, conn->port, conn->fd);
}

static void recv_from_conn(struct http_req_queue *req_queue, struct tcp_conn_table *conn_table, struct tcp_conn *conn) {
    ssize_t num_bytes = recv(conn->fd, conn->buf + conn->buf_len, conn->buf_cap - conn->buf_len, MSG_DONTWAIT);
    if (num_bytes < 0) {
        // TODO: Handle error better.
        LOG_FATAL("recv() on connection %s:%d (fd=%d) failed, errno=%d (%s)", conn->ip, conn->port, conn->fd, errno,
                  strerror(errno));
    }
    if (num_bytes == 0) {
        LOG_WARN("Spurious wake-up of connection %s:%d (fd=%d), had no bytes to read", conn->ip, conn->port, conn->fd);
        return;
    }
    LOG_DEBUG("Received %zu bytes from %s:%d (fd=%d)", num_bytes, conn->ip, conn->port, conn->fd);
    conn->buf_len += num_bytes;
    conn->buf[conn->buf_len] = 0;
    int bytes_read = read_http_reqs(req_queue, &conn->cur_req, conn->buf, conn->fd);
    if (bytes_read < 0) {
        // Errors logged in read_http_reqs.
        close_conn(req_queue, conn_table, conn);
    } else {
        if (bytes_read != conn->buf_len) {
            memcpy(conn->buf, conn->buf + bytes_read, conn->buf_len - bytes_read);
        }
        conn->buf_len -= bytes_read;
        if (conn->buf_len == conn->buf_cap) {
            LOG_ERROR(
                "Buffer for connection %s:%d (fd=%d) is filled by a single HTTP request, will close this connection",
                conn->ip, conn->port, conn->fd);
            close_conn(req_queue, conn_table, conn);
        }
    }
}

void run_tcp_server(struct http_req_queue *req_queue, struct tcp_conn_table *conn_table, int port, int max_clients) {
    int listen_fd = create_server_socket(port, max_clients);

    int kqueue_id = kqueue();
    if (kqueue_id < 0) {
        LOG_FATAL("Failed to start server: kqueue() failed errno=%d (%s)", errno, strerror(errno));
    }

    struct kevent event;
    EV_SET(&event, listen_fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, 0);
    if (kevent(kqueue_id, &event, 1, 0, 0, 0) < 0 && errno != EINTR) {
        LOG_FATAL("Failed to start server: kevent() failed errno=%d (%s)", errno, strerror(errno));
    }

    LOG_INFO("Running HTTP server on port %d", port);

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
        if (event_fd == listen_fd) {
            LOG_DEBUG("Received kevent on TCP server socket (fd=%d)", listen_fd);
            conn = accept_conn(conn_table, listen_fd);
            if (conn != 0) {
                EV_SET(&event, conn->fd, EVFILT_READ, EV_ADD, 0, 0, 0);
                if (kevent(kqueue_id, &event, 1, 0, 0, 0) < 0 && errno != EINTR) {
                    LOG_ERROR("Could not accept TCP connection from %s:%d (fd=%d), kevent() failed errno=%d (%s)",
                              conn->ip, conn->port, conn->fd, errno, strerror(errno));
                    close_conn(req_queue, conn_table, conn);
                }
            }
        } else {
            conn = tcp_conn_table_lookup(conn_table, event_fd);
            if (conn == 0) {
                LOG_WARN("Received kevent() on fd=%d, but could not find connection", event_fd);
            } else {
                LOG_DEBUG("Received kevent on connection %s:%d (fd=%d)", conn->ip, conn->port, conn->fd);
                if (event.flags & EV_EOF) {
                    close_conn(req_queue, conn_table, conn);
                } else if (event.filter & EVFILT_READ) {
                    recv_from_conn(req_queue, conn_table, conn);
                } else {
                    LOG_ERROR("Received unexpected event from kevent() fd=%d, event.flags=%d, event.filter=%u",
                              event_fd, event.flags, event.filter);
                }
            }
        }
    }
}
