#include <errno.h>
#include <stdlib.h>
#include <sys/epoll.h>

#include "../logging/logging.h"
#include "tcp_server.h"
#include "tcp_write_loop.h"

void init_write_loop(struct tcp_write_loop* w_loop) {
    w_loop->loop_fd = epoll_create1(0);
    if (w_loop->loop_fd < 0) {
        LOG_FATAL("Failed to initialize write worker loop, epoll_create1() failed errno=%d (%s)", errno,
                  errno_str(errno));
    }
    struct epoll_event event;
    event.events = EPOLLIN;
    event.data.ptr = &w_loop->loop_notify_pipe[0];
    if (epoll_ctl(w_loop->loop_fd, EPOLL_CTL_ADD, w_loop->loop_notify_pipe[0], &event) < 0 && errno != EINTR) {
        LOG_FATAL("Failed to attach notify pipe to write worker loop, epoll_ctl() failed errno=%d (%s)", errno,
                  errno_str(errno));
    }
}

void run_write_loop(struct tcp_write_loop* w_loop) {
    struct epoll_event* events = malloc(sizeof(struct epoll_event) * w_loop->loop_max_events);
    if (events == 0) {
        LOG_FATAL("Failed to allocate %d epoll_events for the write loop (malloc failed for %zu bytes)",
                  w_loop->loop_max_events, sizeof(struct epoll_event) * w_loop->loop_max_events);
    }
    while (1) {
        int n_ev = epoll_wait(w_loop->loop_fd, events, w_loop->loop_max_events, -1);
        if (n_ev < 0) {
            // TODO: Handle error better.
            LOG_FATAL("Write worker loop: epoll_wait() failed errno=%d (%s)", errno, errno_str(errno));
        }

        if (n_ev == 0) {
            LOG_WARN("Write worker loop: Spurious wake-up from epoll_wait()");
            continue;
        }

        int should_process_notification = 0;
        for (int i = 0; i < n_ev; i++) {
            if ((events[i].events & EPOLLIN) == 0) {
                continue;
            }
            if (events[i].data.ptr == &w_loop->loop_notify_pipe[0]) {
                should_process_notification = 1;
            } else {
                tcp_write_loop_process_writes(events[i].data.ptr);
            }
        }
        if (should_process_notification) {
            tcp_write_loop_process_notification(w_loop);
        }
    }
}

int write_loop_add_conn(struct tcp_conn* conn) {
    struct epoll_event event;
    event.events = EPOLLOUT;  // TODO: | EPOLLET;
    event.data.ptr = conn;
    if (epoll_ctl(conn->server->w_loop.loop_fd, EPOLL_CTL_ADD, conn->fd, &event) < 0) {
        LOG_ERROR("epoll_ctl() failed errno=%d (%s)", errno, errno_str(errno));
        return -1;
    }
    return 0;
}

void write_loop_remove_conn(struct tcp_conn* conn) {
    struct epoll_event event;
    event.events = EPOLLOUT;  // TODO: | EPOLLET;
    event.data.ptr = conn;
    if (epoll_ctl(conn->server->w_loop.loop_fd, EPOLL_CTL_DEL, conn->fd, &event) < 0) {
        LOG_ERROR("epoll_ctl() failed errno=%d (%s)", errno, errno_str(errno));
    }
}
