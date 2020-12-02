#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <unistd.h>

#include "logging.h"
#include "tcp_server.h"
#include "write_queue.h"
#include "write_worker_loop.h"

struct write_worker_loop {
    int kqueue_fd;
    int notify_pipe_read_fd;
};

struct write_worker_loop* new_write_worker_loop(int notify_pipe_read_fd) {
    struct write_worker_loop* loop = malloc(sizeof(struct write_worker_loop));
    if (loop == 0) {
        LOG_FATAL("Failed to allocate write worker loop");
    }
    loop->kqueue_fd = kqueue();
    if (loop->kqueue_fd < 0) {
        LOG_FATAL("Failed to initialize write worker loop, kqueue() failed errno=%d (%s)", errno, strerror(errno));
    }
    loop->notify_pipe_read_fd = notify_pipe_read_fd;
    struct kevent ev;
    EV_SET(&ev, notify_pipe_read_fd, EVFILT_READ, EV_ADD, 0, 0, 0);
    if (kevent(loop->kqueue_fd, &ev, 1, 0, 0, 0) < 0) {
        LOG_FATAL("Failed to attach notify pipe to write worker loop, kevent() failed errno=%d (%s)", errno,
                  strerror(errno));
    }
    return loop;
}

void write_worker_loop_run(struct write_worker_loop* loop, struct write_queue* write_queue) {
    struct kevent event;
    while (1) {
        int n_ev = kevent(loop->kqueue_fd, 0, 0, &event, 1, 0);
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
        if (event_fd == loop->notify_pipe_read_fd) {
            write_queue_process_notification(write_queue);
        } else {
            write_queue_process_writes(write_queue, event_fd);
        }
    }
}

int write_worker_loop_add_fd(struct write_worker_loop* loop, int fd) {
    struct kevent ev;
    EV_SET(&ev, fd, EVFILT_WRITE, EV_ADD, 0, 0, 0);
    if (kevent(loop->kqueue_fd, &ev, 1, 0, 0, 0) < 0) {
        LOG_ERROR("kevent() failed errno=%d (%s)", errno, strerror(errno));
        return -1;
    }
    return 0;
}
