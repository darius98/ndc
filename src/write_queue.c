#include "write_queue.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fd.h"
#include "logging.h"
#include "tcp_server.h"

static void init_tasks_list_table(struct write_task_list_table* table, int n_buckets, int bucket_init_cap) {
    atomic_store_explicit(&table->size, 0, memory_order_release);
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
        ff_pthread_mutex_init(&table->buckets[i].lock, 0);
        ff_pthread_mutex_init(&table->buckets[i].task_list_lock, 0);
    }
}

static struct write_task_list_table_bucket* fd_bucket(struct write_queue* queue, int fd) {
    return &queue->task_lists.buckets[fd % queue->task_lists.n_buckets];
}

static struct write_task_list_table_bucket* task_list_bucket(struct write_queue* queue,
                                                             struct write_task_list* task_list) {
    return fd_bucket(queue, task_list->conn->fd);
}

static void lock_task_list(struct write_queue* queue, struct write_task_list* task_list) {
    ff_pthread_mutex_lock(&task_list_bucket(queue, task_list)->task_list_lock);
}

static void unlock_task_list(struct write_queue* queue, struct write_task_list* task_list) {
    ff_pthread_mutex_unlock(&task_list_bucket(queue, task_list)->task_list_lock);
}

static struct write_task* write_queue_top(struct write_queue* queue, struct write_task_list* task_list) {
    struct write_task* task;
    lock_task_list(queue, task_list);
    task = task_list->head;
    unlock_task_list(queue, task_list);
    return task;
}

static void write_queue_pop(struct write_queue* queue, struct write_task_list* task_list, int err) {
    struct write_task* task;
    lock_task_list(queue, task_list);
    task = task_list->head;
    task_list->head = task->next;
    if (task_list->head == 0) {
        task_list->tail = 0;
    }
    task->next = 0;
    unlock_task_list(queue, task_list);
    task->cb(task->cb_data, task_list->conn, err);
    free(task);
}

static void write_queue_pop_all(struct write_queue* queue, struct write_task_list* task_list, int err) {
    struct write_task* task;
    lock_task_list(queue, task_list);
    task = task_list->head;
    task_list->head = 0;
    task_list->tail = 0;
    unlock_task_list(queue, task_list);
    while (task != 0) {
        struct write_task* next = task->next;
        task->cb(task->cb_data, task_list->conn, err);
        free(task);
        task = next;
    }
}

static void add_task_list(struct write_queue* queue, struct tcp_conn* conn) {
    struct write_task_list* task_list = malloc(sizeof(struct write_task_list));
    if (task_list == 0) {
        LOG_ERROR("Failed to allocate write task list for connection %s:%d", ipv4_str(conn->ipv4), conn->port);
        tcp_conn_dec_refcount(conn);
        return;
    }
    atomic_store_explicit(&task_list->ref_count, 1, memory_order_release);
    task_list->conn = conn;
    task_list->head = 0;
    task_list->tail = 0;

    struct write_task_list_table_bucket* bucket = task_list_bucket(queue, task_list);
    ff_pthread_mutex_lock(&bucket->lock);
    if (bucket->len == bucket->cap) {
        void* resized = realloc(bucket->entries, sizeof(void*) * bucket->cap * 2);
        if (resized == 0) {
            ff_pthread_mutex_unlock(&bucket->lock);
            tcp_conn_dec_refcount(conn);
            free(task_list);
            return;
        }
        bucket->entries = resized;
        bucket->cap *= 2;
    }
    bucket->entries[bucket->len++] = task_list;
    ff_pthread_mutex_unlock(&bucket->lock);
    atomic_fetch_add_explicit(&queue->task_lists.size, 1, memory_order_release);
}

static int release_task_list(struct write_queue* queue, struct write_task_list* task_list) {
    if (atomic_fetch_sub_explicit(&task_list->ref_count, 1, memory_order_acq_rel) == 1) {
        write_queue_pop_all(queue, task_list, ECONNABORTED);
        LOG_DEBUG("Reclaiming memory for write_task_list for connection %s:%d (fd=%d)", ipv4_str(task_list->conn->ipv4),
                  task_list->conn->port, task_list->conn->fd);
        tcp_conn_dec_refcount(task_list->conn);
        free(task_list);
        return 1;
    }
    return 0;
}

static void remove_task_list(struct write_queue* queue, int fd) {
    struct write_task_list* task_list = 0;
    struct write_task_list_table_bucket* bucket = fd_bucket(queue, fd);
    ff_pthread_mutex_lock(&bucket->lock);
    for (int i = 0; i < bucket->len; i++) {
        if (bucket->entries[i]->conn->fd == fd) {
            task_list = bucket->entries[i];
            bucket->entries[i] = bucket->entries[bucket->len - 1];
            bucket->len--;
            break;
        }
    }
    ff_pthread_mutex_unlock(&bucket->lock);
    if (task_list != 0) {
        if (release_task_list(queue, task_list)) {
            atomic_fetch_sub_explicit(&queue->task_lists.size, 1, memory_order_release);
        }
    }
}

static struct write_task_list* get_task_list(struct write_queue* queue, int fd) {
    struct write_task_list* task_list = 0;
    struct write_task_list_table_bucket* bucket = fd_bucket(queue, fd);
    ff_pthread_mutex_lock(&bucket->lock);
    for (int i = 0; i < bucket->len; i++) {
        if (bucket->entries[i]->conn->fd == fd) {
            task_list = bucket->entries[i];
            atomic_fetch_add_explicit(&task_list->ref_count, 1, memory_order_release);
            break;
        }
    }
    ff_pthread_mutex_unlock(&bucket->lock);
    return task_list;
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
    if (pipe(queue->loop_notify_pipe) < 0) {
        LOG_FATAL("pipe() failed errno=%d (%s)", errno, errno_str(errno));
    }
    if (set_nonblocking(queue->loop_notify_pipe[0]) < 0) {
        LOG_FATAL("Failed to set read pipe non-blocking for TCP write queue");
    }
    if (set_nonblocking(queue->loop_notify_pipe[1]) < 0) {
        LOG_FATAL("Failed to set write pipe non-blocking for TCP write queue");
    }
    init_write_loop(queue);
    ff_pthread_create(&queue->worker, 0, write_queue_worker, queue);
}

struct write_worker_notification {
    enum
    {
        ww_notify_add,
        ww_notify_execute,
        ww_notify_remove
    } type;
    int fd;
    struct tcp_conn* conn;
    struct write_task* task;
};

static void write_notification(struct write_queue* queue, struct  write_worker_notification notification) {
    int ret = write(queue->loop_notify_pipe[1], &notification, sizeof(struct write_worker_notification));
    if (ret != sizeof(struct write_worker_notification)) {
        if (ret < 0) {
            LOG_FATAL("Failed to write() to TCP server notify pipe errno=%d (%s)", errno, errno_str(errno));
        } else {
            LOG_FATAL("Failed to write() to TCP server notify pipe, wrote %d out of %d bytes.", ret,
                      (int)sizeof(struct write_worker_notification));
        }
    }
}

int write_queue_add_conn(struct write_queue* queue, struct tcp_conn* conn) {
    if (write_loop_add_fd(queue, conn->fd) < 0) {
        return -1;
    }
    tcp_conn_inc_refcount(conn);
    struct write_worker_notification notification;
    notification.conn = conn;
    notification.type = ww_notify_add;
    write_notification(queue, notification);
    return 0;
}

void write_queue_remove_conn(struct write_queue* queue, struct tcp_conn* conn) {
    struct write_worker_notification notification;
    notification.fd = conn->fd;
    notification.type = ww_notify_remove;
    write_notification(queue, notification);
}

void write_queue_push(struct write_queue* queue, struct tcp_conn* conn, const char* buf, int buf_len, void* cb_data,
                      write_task_cb cb) {
    struct write_task* task = malloc(sizeof(struct write_task));
    if (task == 0) {
        LOG_ERROR("Failed to allocate write task for connection %s:%d", ipv4_str(conn->ipv4), conn->port);
        cb(cb_data, conn, -1);
        close_tcp_conn(queue->tcp_server, conn);
        return;
    }

    task->buf_crs = 0;
    task->buf_len = buf_len;
    task->buf = buf;
    task->cb_data = cb_data;
    task->cb = cb;

    struct write_worker_notification notification;
    notification.fd = conn->fd;
    notification.conn = conn;
    notification.task = task;
    notification.type = ww_notify_execute;
    write_notification(queue, notification);
    tcp_conn_inc_refcount(conn); // To make sure the connection stays alive until push_task is executed.
}

static int push_task(struct write_queue* queue, struct tcp_conn* conn, struct write_task* task, int fd) {
    tcp_conn_dec_refcount(conn);
    struct write_task_list* task_list = get_task_list(queue, fd);
    if (task_list == 0) {
        LOG_ERROR("Failed to allocate write task list for connection %s:%d", ipv4_str(conn->ipv4), conn->port);
        task->cb(task->cb_data, conn, -1);
        close_tcp_conn(queue->tcp_server, conn);
        free(task);
        return -1;
    }

    lock_task_list(queue, task_list);
    task->next = 0;
    if (task_list->tail != 0) {
        task_list->tail->next = task;
    }
    task_list->tail = task;
    if (task_list->head == 0) {
        task_list->head = task;
    }
    unlock_task_list(queue, task_list);
    release_task_list(queue, task_list);
    return 0;
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
            LOG_ERROR("write() failed with errno=%d (%s)", errno, errno_str(errno));
            write_queue_pop(queue, task_list, errno);
            close_tcp_conn(queue->tcp_server, task_list->conn);
            break;
        } else if (chunk_sz > 0) {
            LOG_DEBUG("Wrote %d bytes to %s:%d", (int)chunk_sz, ipv4_str(task_list->conn->ipv4), task_list->conn->port);
            task->buf_crs += chunk_sz;
            if (task->buf_crs == task->buf_len) {
                write_queue_pop(queue, task_list, 0);
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
                  errno, errno_str(errno));
    }
    if (notification.type == ww_notify_execute) {
        if (push_task(queue, notification.conn, notification.task, notification.fd) == 0) {
            write_queue_process_writes(queue, notification.fd);
        }
    } else if (notification.type == ww_notify_remove) {
        remove_task_list(queue, notification.fd);
    } else if (notification.type == ww_notify_add) {
        add_task_list(queue, notification.conn);
    }
}
