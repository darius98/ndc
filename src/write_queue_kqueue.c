#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>

#include "logging.h"
#include "tcp_server.h"
#include "write_queue.h"

void init_write_loop(struct write_queue* queue) {
    queue->loop_fd = kqueue();
    if (queue->loop_fd < 0) {
        LOG_FATAL("Failed to initialize write worker loop, kqueue() failed errno=%d (%s)", errno, errno_str(errno));
    }
    struct kevent ev;
    EV_SET(&ev, queue->loop_notify_pipe[0], EVFILT_READ, EV_ADD, 0, 0, 0);
    if (kevent(queue->loop_fd, &ev, 1, 0, 0, 0) < 0) {
        LOG_FATAL("Failed to attach notify pipe to write worker loop, kevent() failed errno=%d (%s)", errno,
                  errno_str(errno));
    }
}

void run_write_loop(struct write_queue* queue) {
    struct kevent* events = malloc(sizeof(struct kevent) * queue->loop_max_events);
    if (events == 0) {
        LOG_FATAL("Failed to allocate %d kevents for the write loop (malloc failed for %zu bytes)",
                  queue->loop_max_events, sizeof(struct kevent) * queue->loop_max_events);
    }
    while (1) {
        int n_ev = kevent(queue->loop_fd, 0, 0, events, queue->loop_max_events, 0);
        if (n_ev < 0) {
            // TODO: Handle error better.
            LOG_FATAL("Write worker loop: kevent() failed errno=%d (%s)", errno, errno_str(errno));
        }

        if (n_ev == 0) {
            LOG_WARN("Write worker loop: Spurious wake-up from kevent()");
            continue;
        }

        for (int i = 0; i < n_ev; i++) {
            int event_fd = (int)events[i].ident;
            if (event_fd == queue->loop_notify_pipe[0]) {
                write_queue_process_notification(queue);
            } else {
                write_queue_process_writes(queue, event_fd);
            }
        }
    }
}

int write_loop_add_fd(struct write_queue* queue, int fd) {
    struct kevent ev;
    EV_SET(&ev, fd, EVFILT_WRITE, EV_ADD, 0, 0, 0);
    if (kevent(queue->loop_fd, &ev, 1, 0, 0, 0) < 0) {
        LOG_ERROR("kevent() failed errno=%d (%s)", errno, errno_str(errno));
        return -1;
    }
    return 0;
}
