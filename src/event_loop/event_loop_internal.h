#ifndef NDC_EVENT_LOOP_EVENT_LOOP_INTERNAL_H_
#define NDC_EVENT_LOOP_EVENT_LOOP_INTERNAL_H_

#include "utils/config.h"

NDC_BEGIN_DECLS

extern const int event_loop_sizeof_event;

extern const char* event_loop_create_loop_syscall_name;

int event_loop_create_loop_fd();

NDC_END_DECLS

#endif
