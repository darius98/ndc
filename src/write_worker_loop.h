#ifndef NDC_WRITE_WORKER_LOOP_H_
#define NDC_WRITE_WORKER_LOOP_H_

struct write_worker_loop;

/// Allocate and initialize a new write_worker_loop.
/// Note: Aborts on failure.
struct write_worker_loop* new_write_worker_loop(int notify_pipe_read_fd);

void write_worker_loop_run(struct write_worker_loop* loop, struct write_queue* write_queue);

int write_worker_loop_add_fd(struct write_worker_loop* loop, int fd);

#endif
