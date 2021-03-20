#include "event_loop.h"

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include "logging/logging.h"
#include "utils/fd.h"
#include "event_loop_internal.h"

void event_loop_init(struct event_loop* loop, int max_events) {
    loop->max_events = max_events;
    loop->events = malloc(event_loop_sizeof_event * loop->max_events);
    if (loop->events == 0) {
        LOG_FATAL("event_loop_init: failed to allocate %d events (malloc failed %d bytes)", loop->max_events,
                  event_loop_sizeof_event * loop->max_events);
    }

    if (make_nonblocking_pipe(loop->notify_pipe) < 0) {
        LOG_FATAL("Failed to create notify pipe for event loop");
    }

    event_loop_init_internal(loop);
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
