#ifndef NDC_EVENT_LOOP_EVENT_LOOP_INTERNAL_H_
#define NDC_EVENT_LOOP_EVENT_LOOP_INTERNAL_H_

#include "utils/config.h"

NDC_BEGIN_DECLS

extern const int event_loop_sizeof_event;

void event_loop_init_internal(struct event_loop* loop);

NDC_END_DECLS

#endif
