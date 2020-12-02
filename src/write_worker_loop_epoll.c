#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

#include "logging.h"
#include "tcp_server.h"
#include "write_queue.h"
#include "write_worker_loop.h"

struct write_worker_loop {
    int epoll_fd;
    int notify_pipe_read_fd;
};

struct write_worker_loop* new_write_worker_loop(int notify_pipe_read_fd) {
    struct write_worker_loop* loop = malloc(sizeof(struct write_worker_loop));
    if (loop == 0) {
        LOG_FATAL("Failed to allocate write worker loop");
    }
    loop->epoll_fd = epoll_create1(0);
    if (loop->epoll_fd < 0) {
        LOG_FATAL("Failed to initialize write worker loop, epoll_create1() failed errno=%d (%s)", errno,
                  strerror(errno));
    }
    loop->notify_pipe_read_fd = notify_pipe_read_fd;
    struct epoll_event event;
    event.events = EPOLLIN;
    event.data.fd = notify_pipe_read_fd;
    if (epoll_ctl(loop->epoll_fd, EPOLL_CTL_ADD, notify_pipe_read_fd, &event) < 0 && errno != EINTR) {
        LOG_FATAL("Failed to attach notify pipe to write worker loop, epoll_ctl() failed errno=%d (%s)", errno,
                  strerror(errno));
    }
    return loop;
}

void write_worker_loop_run(struct write_worker_loop* loop, struct write_queue* write_queue) {
    struct epoll_event event;
    while (1) {
        int n_ev = epoll_wait(loop->epoll_fd, &event, 1, -1);
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
        if (event_fd == loop->notify_pipe_read_fd) {
            write_queue_process_notification(write_queue);
        } else {
            write_queue_process_writes(write_queue, event_fd);
        }
    }
}

int write_worker_loop_add_fd(struct write_worker_loop* loop, int fd) {
    struct epoll_event event;
    event.events = EPOLLIN | EPOLLET;
    event.data.fd = fd;
    if (epoll_ctl(loop->epoll_fd, EPOLL_CTL_ADD, fd, &event) < 0) {
        LOG_ERROR("epoll_ctl() failed errno=%d (%s)", errno, strerror(errno));
        return -1;
    }
    return 0;
}
