#include "write_queue.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "logging.h"
#include "tcp_server.h"

static void init_tasks_list_table(struct write_task_list_table* table, int n_buckets, int bucket_init_cap) {
    table->size = 0;
    table->n_buckets = n_buckets;
    table->buckets = malloc(sizeof(struct write_task_list_table_bucket) * n_buckets);
    if (table->buckets == 0) {
        LOG_FATAL("Failed to allocate buckets array for write task lists table");
    }
    for (int i = 0; i < n_buckets; i++) {
        table->buckets[i].len = 0;
        table->buckets[i].cap = bucket_init_cap;
        table->buckets[i].entries = malloc(sizeof(struct write_task_list*) * bucket_init_cap);
        if (table->buckets[i].entries == 0) {
            LOG_FATAL("Failed to allocate bucket %d for write task lists table", i);
        }
    }
    ASSERT_0(pthread_mutex_init(&table->lock, 0));
}

static struct write_task* write_queue_top(struct write_queue* queue, struct write_task_list* task_list) {
    struct write_task* task;
    ASSERT_0(pthread_mutex_lock(&queue->lock));
    task = task_list->head;
    ASSERT_0(pthread_mutex_unlock(&queue->lock));
    return task;
}

static void write_queue_pop(struct write_queue* queue, struct write_task_list* task_list,
                            struct write_task* expected_task, int err) {
    struct write_task* task;
    ASSERT_0(pthread_mutex_lock(&queue->lock));
    task = task_list->head;
    ASSERT(expected_task == task);
    task_list->head = task->next;
    if (task_list->head == 0) {
        task_list->tail = 0;
    }
    task->next = 0;
    ASSERT_0(pthread_mutex_unlock(&queue->lock));
    task->cb(task->cb_data, task_list->conn, err);
    free(task);
}

static void delete_task_list(struct write_queue* queue, struct write_task_list* task_list) {
    struct write_task* task = write_queue_top(queue, task_list);
    while (task != 0) {
        write_queue_pop(queue, task_list, task, ECONNABORTED);
        task = write_queue_top(queue, task_list);
    }
    LOG_DEBUG("Reclaiming memory for write_task_list for connection %s:%d (fd=%d)", ipv4_str(task_list->conn->ipv4),
              task_list->conn->port, task_list->conn->fd);
    tcp_conn_dec_refcount(task_list->conn);
    free(task_list);
}

static int add_task_list(struct write_task_list_table* table, struct tcp_conn* conn) {
    struct write_task_list* task_list = malloc(sizeof(struct write_task_list));
    if (task_list == 0) {
        LOG_ERROR("Failed to allocate write task list for connection %s:%d", ipv4_str(conn->ipv4), conn->port);
        return -1;
    }
    tcp_conn_inc_refcount(conn);
    task_list->ref_count = 0;
    task_list->conn = conn;
    task_list->head = 0;
    task_list->tail = 0;

    ASSERT_0(pthread_mutex_lock(&table->lock));
    struct write_task_list_table_bucket* bucket = &table->buckets[conn->fd % table->n_buckets];
    if (bucket->len == bucket->cap) {
        void* resized = realloc(bucket->entries, sizeof(void*) * bucket->cap * 2);
        if (resized == 0) {
            ASSERT_0(pthread_mutex_unlock(&table->lock));
            tcp_conn_dec_refcount(conn);
            free(task_list);
            return -1;
        }
        bucket->entries = resized;
        bucket->cap *= 2;
    }
    task_list->ref_count++;
    bucket->entries[bucket->len++] = task_list;
    table->size++;
    ASSERT_0(pthread_mutex_unlock(&table->lock));
    return 0;
}

static void remove_task_list(struct write_queue* queue, int fd) {
    struct write_task_list* task_list = 0;
    ASSERT_0(pthread_mutex_lock(&queue->task_lists.lock));
    struct write_task_list_table_bucket* bucket = &queue->task_lists.buckets[fd % queue->task_lists.n_buckets];
    for (int i = 0; i < bucket->len; i++) {
        if (bucket->entries[i]->conn->fd == fd) {
            task_list = bucket->entries[i];
            task_list->ref_count -= 1;
            if (task_list->ref_count > 0) {
                task_list = 0;
            }
            bucket->entries[i] = bucket->entries[bucket->len - 1];
            bucket->len--;
            queue->task_lists.size--;
            break;
        }
    }
    ASSERT_0(pthread_mutex_unlock(&queue->task_lists.lock));
    if (task_list != 0) {
        delete_task_list(queue, task_list);
    }
}

static struct write_task_list* get_task_list(struct write_queue* queue, int fd) {
    struct write_task_list* task_list = 0;
    ASSERT_0(pthread_mutex_lock(&queue->task_lists.lock));
    struct write_task_list_table_bucket* bucket = &queue->task_lists.buckets[fd % queue->task_lists.n_buckets];
    for (int i = 0; i < bucket->len; i++) {
        if (bucket->entries[i]->conn->fd == fd) {
            task_list = bucket->entries[i];
            task_list->ref_count += 1;
            break;
        }
    }
    ASSERT_0(pthread_mutex_unlock(&queue->task_lists.lock));
    return task_list;
}

static void release_task_list(struct write_queue* queue, struct write_task_list* task_list) {
    ASSERT_0(pthread_mutex_lock(&queue->task_lists.lock));
    task_list->ref_count -= 1;
    if (task_list->ref_count > 0) {
        task_list = 0;
    }
    ASSERT_0(pthread_mutex_unlock(&queue->task_lists.lock));
    if (task_list != 0) {
        delete_task_list(queue, task_list);
    }
}

static void* write_queue_worker(void* arg) {
    struct write_queue* queue = (struct write_queue*)arg;
    run_write_loop(queue);
    return 0;
}

void init_write_queue(struct write_queue* queue, struct tcp_write_queue_conf* conf, struct tcp_server* tcp_server) {
    queue->tcp_server = tcp_server;
    queue->loop_max_events = conf->events_batch_size;
    init_tasks_list_table(&queue->task_lists, conf->num_buckets, conf->bucket_initial_capacity);
    ASSERT_0(pthread_mutex_init(&queue->lock, 0));
    ASSERT_0(pipe(queue->loop_notify_pipe));
    int prev_flags = fcntl(queue->loop_notify_pipe[0], F_GETFD);
    if (prev_flags < 0) {
        LOG_FATAL("fcntl() failed errno=%d (%s)", errno, strerror(errno));
    }
    ASSERT_0(fcntl(queue->loop_notify_pipe[0], F_SETFD, prev_flags | O_NONBLOCK));
    prev_flags = fcntl(queue->loop_notify_pipe[0], F_GETFD);
    if (prev_flags < 0) {
        LOG_FATAL("fcntl() failed errno=%d (%s)", errno, strerror(errno));
    }
    ASSERT_0(fcntl(queue->loop_notify_pipe[1], F_SETFD, prev_flags | O_NONBLOCK));
    init_write_loop(queue);
    ASSERT_0(pthread_create(&queue->worker, 0, write_queue_worker, queue));
}

int write_queue_add_conn(struct write_queue* queue, struct tcp_conn* conn) {
    if (write_loop_add_fd(queue, conn->fd) < 0) {
        return -1;
    }
    if (add_task_list(&queue->task_lists, conn) < 0) {
        return -1;
    }
    return 0;
}

struct write_worker_notification {
    int fd;
    enum
    {
        ww_notify_execute,
        ww_notify_remove
    } type;
};

void write_queue_remove_conn(struct write_queue* queue, struct tcp_conn* conn) {
    struct write_worker_notification notification;
    notification.fd = conn->fd;
    notification.type = ww_notify_remove;
    // TODO: EH.
    write(queue->loop_notify_pipe[1], &notification, sizeof(struct write_worker_notification));
}

void write_queue_push(struct write_queue* queue, struct tcp_conn* conn, const char* buf, int buf_len, void* cb_data,
                      write_task_cb cb) {
    struct write_task_list* task_list = get_task_list(queue, conn->fd);
    if (task_list == 0) {
        LOG_ERROR("Failed to allocate write task list for connection %s:%d", ipv4_str(conn->ipv4), conn->port);
        cb(cb_data, conn, -1);
        close_tcp_conn(queue->tcp_server, conn);
        return;
    }
    struct write_task* task = malloc(sizeof(struct write_task));
    if (task == 0) {
        LOG_ERROR("Failed to allocate write task for connection %s:%d", ipv4_str(conn->ipv4), conn->port);
        cb(cb_data, conn, -1);
        close_tcp_conn(queue->tcp_server, conn);
        release_task_list(queue, task_list);
        return;
    }

    task->buf_crs = 0;
    task->buf_len = buf_len;
    task->buf = buf;
    task->cb_data = cb_data;
    task->cb = cb;

    ASSERT_0(pthread_mutex_lock(&queue->lock));
    task->next = 0;
    if (task_list->tail != 0) {
        task_list->tail->next = task;
    }
    task_list->tail = task;
    if (task_list->head == 0) {
        task_list->head = task;
    }
    ASSERT_0(pthread_mutex_unlock(&queue->lock));
    struct write_worker_notification notification;
    notification.fd = task_list->conn->fd;
    notification.type = ww_notify_execute;
    // TODO: EH.
    write(queue->loop_notify_pipe[1], &notification, sizeof(struct write_worker_notification));
    release_task_list(queue, task_list);
}

void write_queue_process_writes(struct write_queue* queue, int fd) {
    struct write_task_list* task_list = get_task_list(queue, fd);
    if (task_list == 0) {
        LOG_DEBUG("Could not find write task list for fd=%d", fd);
        return;
    }
    struct write_task* task = write_queue_top(queue, task_list);
    while (task != 0) {
        ssize_t chunk_sz = write(fd, task->buf + task->buf_crs, task->buf_len - task->buf_crs);
        if (chunk_sz < 0 && errno != EWOULDBLOCK) {
            LOG_ERROR("write() failed with errno=%d (%s)", errno, strerror(errno));
            write_queue_pop(queue, task_list, task, errno);
            close_tcp_conn(queue->tcp_server, task_list->conn);
            break;
        } else if (chunk_sz > 0) {
            LOG_DEBUG("Wrote %d bytes to %s:%d", (int)chunk_sz, ipv4_str(task_list->conn->ipv4), task_list->conn->port);
            task->buf_crs += chunk_sz;
            if (task->buf_crs == task->buf_len) {
                write_queue_pop(queue, task_list, task, 0);
                task = write_queue_top(queue, task_list);
            }
        }
    }
    release_task_list(queue, task_list);
}

void write_queue_process_notification(struct write_queue* queue) {
    struct write_worker_notification notification;
    errno = 0;
    ssize_t n_bytes = read(queue->loop_notify_pipe[0], &notification, sizeof(struct write_worker_notification));
    if (n_bytes != sizeof(struct write_worker_notification)) {
        LOG_FATAL("Write worker loop: failed to read notification from pipe, returned %d, errno=%d (%s)", (int)n_bytes,
                  errno, strerror(errno));
    }
    if (notification.type == ww_notify_execute) {
        write_queue_process_writes(queue, notification.fd);
    } else if (notification.type == ww_notify_remove) {
        remove_task_list(queue, notification.fd);
    }
}
