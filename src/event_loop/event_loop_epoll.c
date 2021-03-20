#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include "event_loop.h"
#include "event_loop_internal.h"
#include "logging/logging.h"
#include "utils/fd.h"

const char* event_loop_ctl_syscall_name = "epoll_ctl";

const int event_loop_sizeof_event = sizeof(struct epoll_event);

void event_loop_init_internal(struct event_loop* loop) {
    loop->fd = epoll_create1(0);
    if (loop->fd < 0) {
        LOG_FATAL("Failed to initialize event loop, epoll_create1() failed errno=%d (%s)", errno, errno_str(errno));
    }
    struct epoll_event event;
    event.events = EPOLLIN;
    event.data.ptr = &loop->notify_pipe[0];
    if (epoll_ctl(loop->fd, EPOLL_CTL_ADD, loop->notify_pipe[0], &event) < 0) {
        LOG_FATAL("Failed to attach notify pipe to event loop, epoll_ctl() failed errno=%d (%s)", errno,
                  errno_str(errno));
    }
}

static int event_loop_add_fd(struct event_loop* loop, int fd, void* data, int ctl, uint32_t events) {
    struct epoll_event event;
    event.events = events;
    event.data.ptr = data;
    return epoll_ctl(loop->fd, ctl, fd, &event);
}

// TODO: Use the EPOLLET flag for all descriptors.

int event_loop_add_read_fd(struct event_loop* loop, int fd, void* data) {
    return event_loop_add_fd(loop, fd, data, EPOLL_CTL_ADD, EPOLLIN);
}

int event_loop_remove_read_fd(struct event_loop* loop, int fd, void* data) {
    return event_loop_add_fd(loop, fd, data, EPOLL_CTL_DEL, EPOLLIN);
}

int event_loop_add_write_fd(struct event_loop* loop, int fd, void* data) {
    return event_loop_add_fd(loop, fd, data, EPOLL_CTL_ADD, EPOLLOUT);
}

int event_loop_remove_write_fd(struct event_loop* loop, int fd, void* data) {
    return event_loop_add_fd(loop, fd, data, EPOLL_CTL_DEL, EPOLLOUT);
}
