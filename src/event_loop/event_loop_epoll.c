#include <sys/epoll.h>

#include "event_loop.h"
#include "event_loop_internal.h"

const char* event_loop_ctl_syscall_name = "epoll_ctl";

const char* event_loop_create_loop_syscall_name = "epoll_create1";

const int event_loop_sizeof_event = sizeof(struct epoll_event);

int event_loop_create_loop_fd() {
    return epoll_create1(0);
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
