#ifndef NDC_UTILS_FD_H_
#define NDC_UTILS_FD_H_

#include "utils/config.h"

NDC_BEGIN_DECLS

int set_nonblocking(int fd);

int make_nonblocking_pipe(int fd[2]);

int listen_tcp(int port, int backlog);

NDC_END_DECLS

#endif
