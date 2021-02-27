#include <errno.h>
#include <stdlib.h>
#include <sys/event.h>

#include "../logging/logging.h"
#include "tcp_server.h"
#include "tcp_write_loop.h"

void init_write_loop(struct tcp_write_loop* w_loop) {
    w_loop->loop_fd = kqueue();
    if (w_loop->loop_fd < 0) {
        LOG_FATAL("Failed to initialize write worker loop, kqueue() failed errno=%d (%s)", errno, errno_str(errno));
    }
    struct kevent ev;
    EV_SET(&ev, w_loop->loop_notify_pipe[0], EVFILT_READ, EV_ADD, 0, 0, 0);
    if (kevent(w_loop->loop_fd, &ev, 1, 0, 0, 0) < 0) {
        LOG_FATAL("Failed to attach notify pipe to write worker loop, kevent() failed errno=%d (%s)", errno,
                  errno_str(errno));
    }
}

void run_write_loop(struct tcp_write_loop* w_loop) {
    struct kevent* events = malloc(sizeof(struct kevent) * w_loop->loop_max_events);
    if (events == 0) {
        LOG_FATAL("Failed to allocate %d kevents for the write loop (malloc failed for %zu bytes)",
                  w_loop->loop_max_events, sizeof(struct kevent) * w_loop->loop_max_events);
    }
    while (1) {
        int n_ev = kevent(w_loop->loop_fd, 0, 0, events, w_loop->loop_max_events, 0);
        if (n_ev < 0) {
            // TODO: Handle error better.
            LOG_FATAL("Write worker loop: kevent() failed errno=%d (%s)", errno, errno_str(errno));
        }

        if (n_ev == 0) {
            LOG_WARN("Write worker loop: Spurious wake-up from kevent()");
            continue;
        }

        int should_process_notification = 0;
        for (int i = 0; i < n_ev; i++) {
            int event_fd = (int)events[i].ident;
            if (event_fd == w_loop->loop_notify_pipe[0]) {
                should_process_notification = 1;
            } else {
                tcp_write_loop_process_writes(w_loop, events[i].udata);
            }
        }
        if (should_process_notification) {
            tcp_write_loop_process_notification(w_loop);
        }
    }
}

int write_loop_add_conn(struct tcp_write_loop* w_loop, struct tcp_conn* conn) {
    struct kevent ev;
    EV_SET(&ev, conn->fd, EVFILT_WRITE, EV_ADD, 0, 0, conn);
    if (kevent(w_loop->loop_fd, &ev, 1, 0, 0, 0) < 0) {
        LOG_ERROR("kevent() failed errno=%d (%s)", errno, errno_str(errno));
        return -1;
    }
    return 0;
}

void write_loop_remove_conn(struct tcp_write_loop* w_loop, struct tcp_conn* conn) {
    struct kevent ev;
    EV_SET(&ev, conn->fd, EVFILT_WRITE, EV_DELETE, 0, 0, conn);
    if (kevent(w_loop->loop_fd, &ev, 1, 0, 0, 0) < 0) {
        LOG_ERROR("kevent() failed errno=%d (%s)", errno, errno_str(errno));
    }
}
