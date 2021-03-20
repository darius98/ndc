#include "event_loop.h"

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include "event_loop_internal.h"
#include "logging/logging.h"
#include "utils/fd.h"

void event_loop_init(struct event_loop* loop, int max_events) {
    loop->fd = event_loop_create_loop_fd();
    if (loop->fd < 0) {
        LOG_FATAL("event_loop_init: failed to create loop, %s failed errno=%d (%s)",
                  event_loop_create_loop_syscall_name, errno, errno_str(errno));
    }

    if (make_nonblocking_pipe(loop->notify_pipe) < 0) {
        LOG_FATAL("event_loop_init: failed to create notify pipe");
    }

    if (event_loop_add_read_fd(loop, loop->notify_pipe[0], 0) < 0) {
        LOG_FATAL("event_loop_init: failed to attach notify pipe to event loop, %s failed errno=%d (%s)",
                  event_loop_ctl_syscall_name, errno, errno_str(errno));
    }

    loop->max_events = max_events;
    loop->events = malloc(event_loop_sizeof_event * loop->max_events);
    if (loop->events == 0) {
        LOG_FATAL("event_loop_init: failed to allocate %d events (malloc failed for %d bytes)", loop->max_events,
                  event_loop_sizeof_event * loop->max_events);
    }
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
