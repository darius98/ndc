#include "event_loop.h"

#ifdef NDC_USE_KQUEUE
#include <sys/event.h>
#else
#include <sys/epoll.h>
#endif

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include "logging/logging.h"
#include "utils/fd.h"

void event_loop_init(struct event_loop* loop, int max_events) {
    loop->max_events = max_events;
    loop->events = malloc(event_loop_sizeof_event() * loop->max_events);
    if (loop->events == 0) {
        LOG_FATAL("event_loop_init: failed to allocate %d events (malloc failed %d bytes)", loop->max_events,
                  event_loop_sizeof_event() * loop->max_events);
    }

    if (make_nonblocking_pipe(loop->notify_pipe) < 0) {
        LOG_FATAL("Failed to create notify pipe for event loop");
    }

#ifdef NDC_USE_KQUEUE
    loop->fd = kqueue();
    if (loop->fd < 0) {
        LOG_FATAL("Failed to initialize event loop, kqueue() failed errno=%d (%s)", errno, errno_str(errno));
    }
    struct kevent ev;
    EV_SET(&ev, loop->notify_pipe[0], EVFILT_READ, EV_ADD, 0, 0, 0);
    if (kevent(loop->fd, &ev, 1, 0, 0, 0) < 0) {
        LOG_FATAL("Failed to attach notify pipe to event loop, kevent() failed errno=%d (%s)", errno, errno_str(errno));
    }
#else
    loop->fd = epoll_create1(0);
    if (loop->fd < 0) {
        LOG_FATAL("Failed to initialize event loop, epoll_create1() failed errno=%d (%s)", errno, errno_str(errno));
    }
    struct epoll_event event;
    event.events = EPOLLIN;
    event.data.ptr = &loop->notify_pipe[0];
    if (epoll_ctl(loop->fd, EPOLL_CTL_ADD, loop->notify_pipe[0], &event) < 0 && errno != EINTR) {
        LOG_FATAL("Failed to attach notify pipe to event loop, epoll_ctl() failed errno=%d (%s)", errno,
                  errno_str(errno));
    }
#endif
}

void event_loop_send_notification(struct event_loop* loop, const void* payload, int payload_size) {
    int ret = write(loop->notify_pipe[1], payload, payload_size);
    if (ret != payload_size) {
        if (ret < 0) {
            LOG_FATAL("Failed to write() event loop notification errno=%d (%s)", errno, errno_str(errno));
        } else {
            LOG_FATAL("Failed to write() event loop notification, wrote %d out of %d bytes.", ret, payload_size);
        }
    }
}

void event_loop_recv_notification(struct event_loop* loop, void* payload, int payload_size) {
    int ret = read(loop->notify_pipe[0], payload, payload_size);
    if (ret != payload_size) {
        if (ret < 0) {
            LOG_FATAL("Failed to read() event loop notification errno=%d (%s)", errno, errno_str(errno));
        } else {
            LOG_FATAL("Failed to read() event loop notification, read %d out of %d bytes.", ret, payload_size);
        }
    }
}

int event_loop_sizeof_event() {
#ifdef NDC_USE_KQUEUE
    return sizeof(struct kevent);
#else
    return sizeof(struct epoll_event);
#endif
}

int event_loop_add_read_fd(struct event_loop* loop, int fd, void* data) {
#ifdef NDC_USE_KQUEUE
    struct kevent event;
    EV_SET(&event, fd, EVFILT_READ, EV_ADD, 0, 0, data);
    return kevent(loop->fd, &event, 1, 0, 0, 0);
#else
    struct epoll_event event;
    event.events = EPOLLIN;  // TODO: | EPOLLET;
    event.data.ptr = data;
    return epoll_ctl(loop->fd, EPOLL_CTL_ADD, fd, &event);
#endif
}

int event_loop_remove_read_fd(struct event_loop* loop, int fd, void* data) {
#ifdef NDC_USE_KQUEUE
    struct kevent event;
    EV_SET(&event, fd, EVFILT_READ, EV_DELETE, 0, 0, data);
    return kevent(loop->fd, &event, 1, 0, 0, 0);
#else
    struct epoll_event event;
    event.events = EPOLLIN;  // TODO: | EPOLLET;
    event.data.ptr = data;
    return epoll_ctl(loop->fd, EPOLL_CTL_DEL, fd, &event);
#endif
}

int event_loop_add_write_fd(struct event_loop* loop, int fd, void* data) {
#ifdef NDC_USE_KQUEUE
    struct kevent event;
    EV_SET(&event, fd, EVFILT_WRITE, EV_ADD, 0, 0, data);
    return kevent(loop->fd, &event, 1, 0, 0, 0);
#else
    struct epoll_event event;
    event.events = EPOLLOUT;  // TODO: | EPOLLET;
    event.data.ptr = data;
    return epoll_ctl(loop->fd, EPOLL_CTL_ADD, fd, &event);
#endif
}

int event_loop_remove_write_fd(struct event_loop* loop, int fd, void* data) {
#ifdef NDC_USE_KQUEUE
    struct kevent ev;
    EV_SET(&ev, fd, EVFILT_WRITE, EV_DELETE, 0, 0, data);
    return kevent(loop->fd, &ev, 1, 0, 0, 0);
#else
    struct epoll_event event;
    event.events = EPOLLOUT;  // TODO: | EPOLLET;
    event.data.ptr = data;
    return epoll_ctl(loop->fd, EPOLL_CTL_DEL, fd, &event);
#endif
}
