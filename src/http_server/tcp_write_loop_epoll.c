#include <errno.h>
#include <stdlib.h>
#include <sys/epoll.h>

#include "../logging/logging.h"
#include "tcp_server.h"
#include "tcp_write_loop.h"

void run_write_loop(struct event_loop* w_loop) {
    struct epoll_event* events = (struct epoll_event*)w_loop->events;
    while (1) {
        int n_ev = epoll_wait(w_loop->fd, events, w_loop->max_events, -1);
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
            if (events[i].data.ptr == &w_loop->notify_pipe[0]) {
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
