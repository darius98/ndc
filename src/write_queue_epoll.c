#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

#include "logging.h"
#include "write_queue.h"

void init_write_loop(struct write_queue* queue) {
    queue->loop_fd = epoll_create1(0);
    if (queue->loop_fd < 0) {
        LOG_FATAL("Failed to initialize write worker loop, epoll_create1() failed errno=%d (%s)", errno,
                  errno_str(errno));
    }
    struct epoll_event event;
    event.events = EPOLLIN;
    event.data.fd = queue->loop_notify_pipe[0];
    if (epoll_ctl(queue->loop_fd, EPOLL_CTL_ADD, queue->loop_notify_pipe[0], &event) < 0 && errno != EINTR) {
        LOG_FATAL("Failed to attach notify pipe to write worker loop, epoll_ctl() failed errno=%d (%s)", errno,
                  errno_str(errno));
    }
}

void run_write_loop(struct write_queue* queue) {
    struct epoll_event* events = malloc(sizeof(struct epoll_event) * queue->loop_max_events);
    if (events == 0) {
        LOG_FATAL("Failed to allocate %d epoll_events for the write loop (malloc failed for %zu bytes)",
                  queue->loop_max_events, sizeof(struct epoll_event) * queue->loop_max_events);
    }
    while (1) {
        int n_ev = epoll_wait(queue->loop_fd, events, queue->loop_max_events, -1);
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
            int event_fd = (int)events[i].data.fd;
            if (event_fd == queue->loop_notify_pipe[0]) {
                should_process_notification = 1;
            } else {
                write_queue_process_writes(queue, event_fd);
            }
        }
        if (should_process_notification) {
            write_queue_process_notification(queue);
        }
    }
}

int write_loop_add_fd(struct write_queue* queue, int fd) {
    struct epoll_event event;
    event.events = EPOLLIN;  // TODO: | EPOLLET;
    event.data.fd = fd;
    if (epoll_ctl(queue->loop_fd, EPOLL_CTL_ADD, fd, &event) < 0) {
        LOG_ERROR("epoll_ctl() failed errno=%d (%s)", errno, errno_str(errno));
        return -1;
    }
    return 0;
}

void write_loop_remove_fd(struct write_queue* queue, int fd) {
    struct epoll_event event;
    event.events = EPOLLIN;  // TODO: | EPOLLET;
    event.data.fd = fd;
    if (epoll_ctl(queue->loop_fd, EPOLL_CTL_DEL, fd, &event) < 0) {
        LOG_ERROR("epoll_ctl() failed errno=%d (%s)", errno, errno_str(errno));
    }
}
