#include <sys/event.h>

#include "event_loop.h"
#include "event_loop_internal.h"

const char* event_loop_ctl_syscall_name = "kevent";

const char* event_loop_run_syscall_name = "kevent";

const char* event_loop_create_loop_syscall_name = "kqueue";

const int event_loop_sizeof_event = sizeof(struct kevent);

int event_loop_create_loop_fd() {
    return kqueue();
}

static int event_loop_ctl(struct event_loop* loop, int fd, void* data, int16_t filter, uint16_t flags) {
    struct kevent event;
    EV_SET(&event, fd, filter, flags, 0, 0, data);
    return kevent(loop->fd, &event, 1, 0, 0, 0);
}

int event_loop_add_read_fd(struct event_loop* loop, int fd, void* data) {
    return event_loop_ctl(loop, fd, data, EVFILT_READ, EV_ADD);
}

int event_loop_remove_read_fd(struct event_loop* loop, int fd, void* data) {
    return event_loop_ctl(loop, fd, data, EVFILT_READ, EV_DELETE);
}

int event_loop_add_write_fd(struct event_loop* loop, int fd, void* data) {
    return event_loop_ctl(loop, fd, data, EVFILT_WRITE, EV_ADD);
}

int event_loop_remove_write_fd(struct event_loop* loop, int fd, void* data) {
    return event_loop_ctl(loop, fd, data, EVFILT_WRITE, EV_DELETE);
}

int event_loop_run(struct event_loop* loop, void* cb_data, event_loop_event_cb event_cb,
                   event_loop_notification_ready_cb notification_ready_cb) {
    struct kevent* events = (struct kevent*)loop->events;
    while (1) {
        int n_ev = kevent(loop->fd, 0, 0, events, loop->max_events, 0);
        if (n_ev < 0) {
            return -1;
        }

        int should_process_notification = 0;
        for (int i = 0; i < n_ev; i++) {
            int event_fd = (int)events[i].ident;
            if (event_fd == loop->notify_pipe[0]) {
                should_process_notification = 1;
            } else {
                int event_flags = 0;
                if (events[i].filter & EVFILT_READ) {
                    event_flags |= evf_read;
                }
                if (events[i].filter & EVFILT_WRITE) {
                    event_flags |= evf_write;
                }
                if (events[i].flags & EV_EOF) {
                    event_flags |= evf_eof;
                }
                int event_cb_status = event_cb(events[i].udata, event_flags, cb_data);
                if (event_cb_status != 0) {
                    return event_cb_status;
                }
            }
        }
        if (should_process_notification) {
            // Process notifications last, because in case we free memory attached to an event
            // because of a notification, the user data in other events might become dangling
            // pointers.
            int notification_ready_cb_status = notification_ready_cb(cb_data);
            if (notification_ready_cb_status != 0) {
                return notification_ready_cb_status;
            }
        }
    }
}
