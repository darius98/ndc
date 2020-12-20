#include "fd.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>

#include "logging.h"

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

int make_nonblocking_pipe(int fd[2]) {
    if (pipe(fd) < 0) {
        LOG_ERROR("pipe() failed errno=%d (%s)", errno, errno_str(errno));
        return -1;
    }
    if (set_nonblocking(fd[0]) < 0) {
        return -1;
    }
    if (set_nonblocking(fd[1]) < 0) {
        return -1;
    }
    return 0;
}

int listen_tcp(int port, int backlog) {
    int fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        LOG_ERROR("socket() failed errno=%d (%s)", errno, errno_str(errno));
        return -1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(struct sockaddr_in));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(port);
    if (bind(fd, (const struct sockaddr*)&server_addr, sizeof(struct sockaddr_in)) < 0) {
        LOG_ERROR("bind() failed errno=%d (%s)", errno, errno_str(errno));
        return -1;
    }

    if (listen(fd, backlog) < 0) {
        LOG_ERROR("listen() failed errno=%d (%s)", errno, errno_str(errno));
        return -1;
    }

    return fd;
}
