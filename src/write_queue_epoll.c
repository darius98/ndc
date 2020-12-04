#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

#include "logging.h"
#include "tcp_server.h"
#include "write_queue.h"

void init_write_loop(struct write_queue* queue) {
    queue->loop_fd = epoll_create1(0);
    if (queue->loop_fd < 0) {
        LOG_FATAL("Failed to initialize write worker loop, epoll_create1() failed errno=%d (%s)", errno,
                  strerror(errno));
    }
    struct epoll_event event;
    event.events = EPOLLIN;
    event.data.fd = queue->worker_loop_notify_pipe[0];
    if (epoll_ctl(queue->loop_fd, EPOLL_CTL_ADD, queue->worker_loop_notify_pipe[0], &event) < 0 && errno != EINTR) {
        LOG_FATAL("Failed to attach notify pipe to write worker loop, epoll_ctl() failed errno=%d (%s)", errno,
                  strerror(errno));
    }
}

void run_write_loop(struct write_queue* queue) {
    struct epoll_event event;
    while (1) {
        int n_ev = epoll_wait(queue->loop_fd, &event, 1, -1);
        if (n_ev < 0) {
            // TODO: Handle error better.
            LOG_FATAL("Write worker loop: epoll_wait() failed errno=%d (%s)", errno, strerror(errno));
        }

        if (n_ev == 0) {
            LOG_WARN("Write worker loop: Spurious wake-up from epoll_wait()");
            continue;
        }

        if (n_ev != 1) {
            LOG_ERROR("Write worker loop: epoll_wait() returned %d events when capacity was 1.", n_ev);
        }
        int event_fd = (int)event.data.fd;
        if (event_fd == queue->worker_loop_notify_pipe[0]) {
            write_queue_process_notification(queue);
        } else {
            write_queue_process_writes(queue, event_fd);
        }
    }
}

int write_loop_add_fd(struct write_queue* queue, int fd) {
    struct epoll_event event;
    event.events = EPOLLIN | EPOLLET;
    event.data.fd = fd;
    if (epoll_ctl(queue->loop_fd, EPOLL_CTL_ADD, fd, &event) < 0) {
        LOG_ERROR("epoll_ctl() failed errno=%d (%s)", errno, strerror(errno));
        return -1;
    }
    return 0;
}
