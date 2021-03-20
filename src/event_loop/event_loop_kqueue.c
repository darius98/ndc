#include <sys/event.h>

#include "event_loop.h"
#include "event_loop_internal.h"

const char* event_loop_ctl_syscall_name = "kevent";

const char* event_loop_create_loop_syscall_name = "kqueue";

const int event_loop_sizeof_event = sizeof(struct kevent);

int event_loop_create_loop_fd() {
    return kqueue();
}

static int event_loop_add_fd(struct event_loop* loop, int fd, void* data, int16_t filter, uint16_t flags) {
    struct kevent event;
    EV_SET(&event, fd, filter, flags, 0, 0, data);
    return kevent(loop->fd, &event, 1, 0, 0, 0);
}

int event_loop_add_read_fd(struct event_loop* loop, int fd, void* data) {
    return event_loop_add_fd(loop, fd, data, EVFILT_READ, EV_ADD);
}

int event_loop_remove_read_fd(struct event_loop* loop, int fd, void* data) {
    return event_loop_add_fd(loop, fd, data, EVFILT_READ, EV_DELETE);
}

int event_loop_add_write_fd(struct event_loop* loop, int fd, void* data) {
    return event_loop_add_fd(loop, fd, data, EVFILT_WRITE, EV_ADD);
}

int event_loop_remove_write_fd(struct event_loop* loop, int fd, void* data) {
    return event_loop_add_fd(loop, fd, data, EV_DELETE, EV_ADD);
}
