#include <sys/epoll.h>

#include "event_loop.h"
#include "event_loop_internal.h"

const char* event_loop_ctl_syscall_name = "epoll_ctl";

const char* event_loop_create_loop_syscall_name = "epoll_create1";

const int event_loop_sizeof_event = sizeof(struct epoll_event);

int event_loop_create_loop_fd() {
    return epoll_create1(0);
}

static int event_loop_ctl(struct event_loop* loop, int fd, void* data, int ctl, uint32_t events) {
    struct epoll_event event;
    event.events = events;
    event.data.ptr = data;
    return epoll_ctl(loop->fd, ctl, fd, &event);
}

// TODO: Use the EPOLLET flag for all descriptors.

int event_loop_add_read_fd(struct event_loop* loop, int fd, void* data) {
    return event_loop_ctl(loop, fd, data, EPOLL_CTL_ADD, EPOLLIN);
}

int event_loop_remove_read_fd(struct event_loop* loop, int fd, void* data) {
    return event_loop_ctl(loop, fd, data, EPOLL_CTL_DEL, EPOLLIN);
}

int event_loop_add_write_fd(struct event_loop* loop, int fd, void* data) {
    return event_loop_ctl(loop, fd, data, EPOLL_CTL_ADD, EPOLLOUT);
}

int event_loop_remove_write_fd(struct event_loop* loop, int fd, void* data) {
    return event_loop_ctl(loop, fd, data, EPOLL_CTL_DEL, EPOLLOUT);
}

void event_loop_run(struct event_loop* loop, void* cb_data, event_loop_event_cb event_cb,
                    event_loop_notification_ready_cb notification_ready_cb) {
    struct epoll_event *events = (struct epoll_event *)loop->events;
    while (1) {
        int n_ev = epoll_wait(loop->fd, events, loop->max_events, -1);
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
            if (events[i].data.ptr == &loop->notify_pipe[0]) {
                should_process_notification = 1;
            } else {
                // TODO: Do something with EPOLLRDHUP
                int event_flags = 0;
                if (events[i].events & EPOLLIN) {
                    event_flags |= evf_read;
                }
                if (events[i].events & EPOLLOUT) {
                    event_flags |= evf_write;
                }
                event_cb(events[i].data.ptr, event_flags, cb_data);
            }
        }
        if (should_process_notification) {
            notification_ready_cb(cb_data);
        }
    }
}
