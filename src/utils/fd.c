#include "fd.h"

#include <errno.h>
#include <fcntl.h>

#include "../logging/logging.h"

int set_nonblocking(int fd) {
    int prev_flags = fcntl(fd, F_GETFD);
    if (prev_flags < 0) {
        LOG_ERROR("fcntl() failed errno=%d (%s)", errno, errno_str(errno));
        return -1;
    }
    if (fcntl(fd, F_SETFD, prev_flags | O_NONBLOCK) < 0) {
        LOG_ERROR("fcntl() failed errno=%d (%s)", errno, errno_str(errno));
        return -1;
    }
    return 0;
}
