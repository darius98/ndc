#include "write_queue.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <zconf.h>

#include "logging.h"
#include "tcp_server.h"

struct write_task {
    struct tcp_conn* conn;
    int buf_crs;
    int buf_len;
    const char* buf;
    void* cb_data;
    write_task_cb cb;
    struct write_task* next;
};

struct write_queue {
    pthread_mutex_t lock;

    // TODO: Remove when using an event loop.
    pthread_cond_t cond;

    atomic_int worker_stopped;
    pthread_t worker;

    // TODO: Remove when using an event loop.
    struct write_task* head;
    struct write_task* tail;
};

static struct write_task* write_queue_pop(struct write_queue* queue) {
    struct write_task* task;
    ASSERT_0(pthread_mutex_lock(&queue->lock));
    while (1) {
        task = queue->head;
        if (task == 0) {
            ASSERT_0(pthread_cond_wait(&queue->cond, &queue->lock));
        } else {
            queue->head = task->next;
            if (queue->head == 0) {
                queue->tail = 0;
            }
            task->next = 0;
            break;
        }
    }
    ASSERT_0(pthread_mutex_unlock(&queue->lock));
    return task;
}

static void complete_write_task_sync(struct write_task* task) {
    int written_sz = 0;
    while (written_sz < task->buf_len) {
        ssize_t chunk_sz = write(task->conn->fd, task->buf + written_sz, task->buf_len - written_sz);
        if (chunk_sz < 0) {
            LOG_ERROR("write() failed with errno=%d (%s)", errno, strerror(errno));
            task->cb(task->cb_data, task->conn, errno);
            // TODO: Force-close the TCP connection on error, to avoid sending corrupt data!
            tcp_conn_dec_refcount(task->conn);
            free(task);
            return;
        }
        written_sz += chunk_sz;
    }
    LOG_DEBUG("Wrote %d bytes to %s:%d", task->buf_len, ipv4_str(task->conn->ipv4), task->conn->port);
    task->cb(task->cb_data, task->conn, 0);
    tcp_conn_dec_refcount(task->conn);
    free(task);
}

// TODO: Implement this worker as an event loop (epoll/kqueue) to write data whenever the socket is ready to receive it.
void* write_queue_worker(void* arg) {
    struct write_queue* queue = (struct write_queue*)arg;
    while (atomic_load_explicit(&queue->worker_stopped, memory_order_acquire) == 0) {
        struct write_task* task = write_queue_pop(queue);
        complete_write_task_sync(task);
    }
    return 0;
}

struct write_queue* new_write_queue() {
    struct write_queue* queue = malloc(sizeof(struct write_queue));
    if (queue == 0) {
        return 0;
    }
    ASSERT_0(pthread_mutex_init(&queue->lock, 0));
    ASSERT_0(pthread_cond_init(&queue->cond, 0));
    queue->head = 0;
    queue->tail = 0;
    atomic_store_explicit(&queue->worker_stopped, 0, memory_order_release);
    ASSERT_0(pthread_create(&queue->worker, 0, write_queue_worker, queue));
    return queue;
}

void write_queue_push(struct write_queue* queue, struct tcp_conn* conn, const char* buf, int buf_len, void* cb_data,
                      write_task_cb cb) {
    struct write_task* task = malloc(sizeof(struct write_task));
    if (task == 0) {
        LOG_ERROR("Failed to allocate write task for connection %s:%d", ipv4_str(conn->ipv4), conn->port);
        cb(cb_data, conn, -1);
        // TODO: Force-close the TCP connection on error, to avoid sending corrupt data!
        return;
    }

    tcp_conn_inc_refcount(conn);
    task->conn = conn;
    task->buf_crs = 0;
    task->buf_len = buf_len;
    task->buf = buf;
    task->cb_data = cb_data;
    task->cb = cb;

    ASSERT_0(pthread_mutex_lock(&queue->lock));
    task->next = 0;
    if (queue->tail != 0) {
        queue->tail->next = task;
    }
    queue->tail = task;
    if (queue->head == 0) {
        queue->head = task;
    }
    ASSERT_0(pthread_mutex_unlock(&queue->lock));
    ASSERT_0(pthread_cond_signal(&queue->cond));
}
