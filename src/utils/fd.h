#ifndef NDC_FD_H_
#define NDC_FD_H_

int set_nonblocking(int fd);

int make_nonblocking_pipe(int fd[2]);

int listen_tcp(int port, int backlog);

#endif
