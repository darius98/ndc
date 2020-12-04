#include <errno.h>
#include <string.h>
#include <sys/event.h>

#include "logging.h"
#include "tcp_server.h"
#include "write_queue.h"

void init_write_loop(struct write_queue* queue) {
    queue->loop_fd = kqueue();
    if (queue->loop_fd < 0) {
        LOG_FATAL("Failed to initialize write worker loop, kqueue() failed errno=%d (%s)", errno, strerror(errno));
    }
    struct kevent ev;
    EV_SET(&ev, queue->worker_loop_notify_pipe[0], EVFILT_READ, EV_ADD, 0, 0, 0);
    if (kevent(queue->loop_fd, &ev, 1, 0, 0, 0) < 0) {
        LOG_FATAL("Failed to attach notify pipe to write worker loop, kevent() failed errno=%d (%s)", errno,
                  strerror(errno));
    }
}

void run_write_loop(struct write_queue* queue) {
    struct kevent event;
    while (1) {
        int n_ev = kevent(queue->loop_fd, 0, 0, &event, 1, 0);
        if (n_ev < 0) {
            // TODO: Handle error better.
            LOG_FATAL("Write worker loop: kevent() failed errno=%d (%s)", errno, strerror(errno));
        }

        if (n_ev == 0) {
            LOG_WARN("Write worker loop: Spurious wake-up from kevent()");
            continue;
        }

        if (n_ev != 1) {
            LOG_ERROR("Write worker loop: kevent() returned %d events when capacity was 1.", n_ev);
        }
        int event_fd = (int)event.ident;
        if (event_fd == queue->worker_loop_notify_pipe[0]) {
            write_queue_process_notification(queue);
        } else {
            write_queue_process_writes(queue, event_fd);
        }
    }
}

int write_loop_add_fd(struct write_queue* queue, int fd) {
    struct kevent ev;
    EV_SET(&ev, fd, EVFILT_WRITE, EV_ADD, 0, 0, 0);
    if (kevent(queue->loop_fd, &ev, 1, 0, 0, 0) < 0) {
        LOG_ERROR("kevent() failed errno=%d (%s)", errno, strerror(errno));
        return -1;
    }
    return 0;
}
