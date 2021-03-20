#include <errno.h>
#include <sys/event.h>
#include <unistd.h>

#include "event_loop.h"
#include "event_loop_internal.h"
#include "logging/logging.h"

const char* event_loop_ctl_syscall_name = "kqueue";

const int event_loop_sizeof_event = sizeof(struct kevent);

void event_loop_init_internal(struct event_loop* loop) {
    loop->fd = kqueue();
    if (loop->fd < 0) {
        LOG_FATAL("Failed to initialize event loop, kqueue() failed errno=%d (%s)", errno, errno_str(errno));
    }
    struct kevent ev;
    EV_SET(&ev, loop->notify_pipe[0], EVFILT_READ, EV_ADD, 0, 0, 0);
    if (kevent(loop->fd, &ev, 1, 0, 0, 0) < 0) {
        LOG_FATAL("Failed to attach notify pipe to event loop, kevent() failed errno=%d (%s)", errno, errno_str(errno));
    }
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
