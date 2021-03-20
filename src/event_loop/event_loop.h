#ifndef NDC_EVENT_LOOP_EVENT_LOOP_H_
#define NDC_EVENT_LOOP_EVENT_LOOP_H_

#include "utils/config.h"

NDC_BEGIN_DECLS

struct event_loop {
    int notify_pipe[2];
    int fd;
    int max_events;
    void* events;
};

// Note: Aborts on failure. TODO: Don't.
void event_loop_init(struct event_loop* loop, int max_events);

// Note: Aborts on failure. TODO: Don't.
void event_loop_send_notification(struct event_loop* loop, const void* payload, int payload_size);

// Note: Aborts on failure. TODO: Don't.
void event_loop_recv_notification(struct event_loop* loop, void* payload, int payload_size);

extern const char* event_loop_ctl_syscall_name;

int event_loop_add_read_fd(struct event_loop* loop, int fd, void* data);

int event_loop_remove_read_fd(struct event_loop* loop, int fd, void* data);

int event_loop_add_write_fd(struct event_loop* loop, int fd, void* data);

int event_loop_remove_write_fd(struct event_loop* loop, int fd, void* data);

NDC_END_DECLS

#endif
