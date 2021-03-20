#include <errno.h>
#include <sys/event.h>

#include "../logging/logging.h"
#include "tcp_server.h"
#include "tcp_write_loop.h"

void run_write_loop(struct event_loop* w_loop) {
    struct kevent* events = (struct kevent*)w_loop->events;
    while (1) {
        int n_ev = kevent(w_loop->fd, 0, 0, events, w_loop->max_events, 0);
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
            if (event_fd == w_loop->notify_pipe[0]) {
                should_process_notification = 1;
            } else {
                tcp_write_loop_process_writes(events[i].udata);
            }
        }
        if (should_process_notification) {
            tcp_write_loop_process_notification(w_loop);
        }
    }
}
