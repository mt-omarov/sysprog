#include "thread_pool.h"
#include <pthread.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>

struct thread_task {
    thread_task_f function;
    void *arg;
    void *result;
    bool is_running;
    bool is_finished;
    bool is_pushed;
    bool is_detached;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    struct thread_task *next;
    struct thread_task *prev;
};

struct thread_pool {
    pthread_t *threads;
    int max_thread_count;
    int thread_count;
    int running_tasks;
    int queued_tasks;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    struct thread_task *task_head;
    struct thread_task *task_tail;
    bool is_shutdown;
};

static void *
worker_thread(void *arg);

int
thread_pool_new(int max_thread_count, struct thread_pool **pool)
{
    if (max_thread_count <= 0 || max_thread_count > TPOOL_MAX_THREADS) {
        return TPOOL_ERR_INVALID_ARGUMENT;
    }

    *pool = malloc(sizeof(struct thread_pool));
    if (!*pool) {
        return TPOOL_ERR_INVALID_ARGUMENT;
    }

    (*pool)->threads = malloc(sizeof(pthread_t) * max_thread_count);
    if (!(*pool)->threads) {
        free(*pool);
        return TPOOL_ERR_INVALID_ARGUMENT;
    }

    (*pool)->max_thread_count = max_thread_count;
    (*pool)->thread_count = 0;
    (*pool)->running_tasks = 0;
    (*pool)->queued_tasks = 0;
    (*pool)->task_head = NULL;
    (*pool)->task_tail = NULL;
    (*pool)->is_shutdown = false;

    pthread_mutex_init(&(*pool)->mutex, NULL);
    pthread_cond_init(&(*pool)->cond, NULL);

    return 0;
}

int
thread_pool_thread_count(const struct thread_pool *pool)
{
    pthread_mutex_lock((pthread_mutex_t *)&pool->mutex);
    int count = pool->thread_count;
    pthread_mutex_unlock((pthread_mutex_t *)&pool->mutex);
    return count;
}

int
thread_pool_delete(struct thread_pool *pool)
{
    pthread_mutex_lock(&pool->mutex);

    if (pool->task_head != NULL || pool->running_tasks > 0) {
        pthread_mutex_unlock(&pool->mutex);
        return TPOOL_ERR_HAS_TASKS;
    }

    pool->is_shutdown = true;
    pthread_cond_broadcast(&pool->cond);
    pthread_mutex_unlock(&pool->mutex);

    for (int i = 0; i < pool->thread_count; ++i) {
        pthread_join(pool->threads[i], NULL);
    }

    free(pool->threads);
    pthread_mutex_destroy(&pool->mutex);
    pthread_cond_destroy(&pool->cond);
    free(pool);
    return 0;
}

int
thread_pool_push_task(struct thread_pool *pool, struct thread_task *task)
{
    pthread_mutex_lock(&pool->mutex);

    if (task->is_pushed) {
        pthread_mutex_unlock(&pool->mutex);
        return TPOOL_ERR_TASK_IN_POOL;
    }

    if (pool->queued_tasks + pool->running_tasks >= TPOOL_MAX_TASKS) {
        pthread_mutex_unlock(&pool->mutex);
        return TPOOL_ERR_TOO_MANY_TASKS;
    }

    task->is_pushed = true;
    task->is_finished = false;
    task->is_running = false;
    task->next = NULL;
    task->prev = NULL;

    if (!pool->task_head) {
        pool->task_head = task;
        pool->task_tail = task;
    } else {
        task->next = pool->task_head;
        pool->task_head->prev = task;
        pool->task_head = task;
    }
    pool->queued_tasks++;

    int idle_threads = pool->thread_count - pool->running_tasks;
    if (idle_threads <= 0 && pool->thread_count < pool->max_thread_count) {
        int rc = pthread_create(&pool->threads[pool->thread_count], NULL, worker_thread, pool);
        if (rc == 0) {
            pool->thread_count++;
        }
    }

    pthread_cond_signal(&pool->cond);
    pthread_mutex_unlock(&pool->mutex);
    return 0;
}

int
thread_task_new(struct thread_task **task, thread_task_f function, void *arg)
{
    if (!task || !function) {
        return TPOOL_ERR_INVALID_ARGUMENT;
    }

    *task = malloc(sizeof(struct thread_task));
    if (!*task) {
        return TPOOL_ERR_INVALID_ARGUMENT;
    }

    (*task)->function = function;
    (*task)->arg = arg;
    (*task)->result = NULL;
    (*task)->is_running = false;
    (*task)->is_finished = false;
    (*task)->is_pushed = false;
    (*task)->is_detached = false;
    (*task)->next = NULL;
    (*task)->prev = NULL;
    pthread_mutex_init(&(*task)->mutex, NULL);
    pthread_cond_init(&(*task)->cond, NULL);
    return 0;
}

static void *
worker_thread(void *arg)
{
    struct thread_pool *pool = arg;

    while (true) {
        pthread_mutex_lock(&pool->mutex);

        while (!pool->task_head && !pool->is_shutdown) {
            pthread_cond_wait(&pool->cond, &pool->mutex);
        }

        if (pool->is_shutdown && !pool->task_head) {
            pthread_mutex_unlock(&pool->mutex);
            break;
        }

        struct thread_task *task = pool->task_head;
        if (task) {
            pool->task_head = task->next;
            if (pool->task_head) {
                pool->task_head->prev = NULL;
            } else {
                pool->task_tail = NULL;
            }
            pool->queued_tasks--;
            pool->running_tasks++;
            pthread_mutex_unlock(&pool->mutex);

            pthread_mutex_lock(&task->mutex);
            task->is_running = true;
            task->is_pushed = false;
            pthread_mutex_unlock(&task->mutex);

            void *res = task->function(task->arg);

            pthread_mutex_lock(&pool->mutex);
            pool->running_tasks--;
            pthread_mutex_unlock(&pool->mutex);

            pthread_mutex_lock(&task->mutex);
            task->result = res;
            task->is_finished = true;
            task->is_running = false;
            pthread_cond_broadcast(&task->cond);
            bool is_detached = task->is_detached;
            pthread_mutex_unlock(&task->mutex);

            if (is_detached) {
                pthread_mutex_destroy(&task->mutex);
                pthread_cond_destroy(&task->cond);
                free(task);
            }
        } else {
            pthread_mutex_unlock(&pool->mutex);
        }
    }

    return NULL;
}

bool
thread_task_is_finished(const struct thread_task *task)
{
    pthread_mutex_lock((pthread_mutex_t *)&task->mutex);
    bool finished = task->is_finished;
    pthread_mutex_unlock((pthread_mutex_t *)&task->mutex);
    return finished;
}

bool
thread_task_is_running(const struct thread_task *task)
{
    pthread_mutex_lock((pthread_mutex_t *)&task->mutex);
    bool running = task->is_running;
    pthread_mutex_unlock((pthread_mutex_t *)&task->mutex);
    return running;
}

int
thread_task_join(struct thread_task *task, void **result)
{
    pthread_mutex_lock(&task->mutex);

    if (!task->is_pushed && !task->is_running && !task->is_finished) {
        pthread_mutex_unlock(&task->mutex);
        return TPOOL_ERR_TASK_NOT_PUSHED;
    }

    while (!task->is_finished && !task->is_detached) {
        pthread_cond_wait(&task->cond, &task->mutex);
    }

    if (task->is_detached) {
        pthread_mutex_unlock(&task->mutex);
        return TPOOL_ERR_TASK_NOT_PUSHED;
    }

    if (result) {
        *result = task->result;
    }

    pthread_mutex_unlock(&task->mutex);
    return 0;
}

#if NEED_TIMED_JOIN
int
thread_task_timed_join(struct thread_task *task, double timeout, void **result)
{
    pthread_mutex_lock(&task->mutex);

    if (!task->is_pushed && !task->is_running && !task->is_finished) {
        pthread_mutex_unlock(&task->mutex);
        return TPOOL_ERR_TASK_NOT_PUSHED;
    }

    if (task->is_detached) {
        pthread_mutex_unlock(&task->mutex);
        return TPOOL_ERR_TASK_NOT_PUSHED;
    }

    if (task->is_finished) {
        if (result) {
            *result = task->result;
        }
        pthread_mutex_unlock(&task->mutex);
        return 0;
    }

    if (timeout <= 0) {
        pthread_mutex_unlock(&task->mutex);
        return TPOOL_ERR_TIMEOUT;
    }

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    time_t sec = (time_t) timeout;
    long nsec = (long) ((timeout - (double) sec) * 1000000000L);
    ts.tv_sec += sec;
    ts.tv_nsec += nsec;
    if (ts.tv_nsec >= 1000000000L) {
        ts.tv_sec += ts.tv_nsec / 1000000000L;
        ts.tv_nsec %= 1000000000L;
    }

    while (!task->is_finished && !task->is_detached) {
        int rc = pthread_cond_timedwait(&task->cond, &task->mutex, &ts);
        if (rc == ETIMEDOUT) {
            pthread_mutex_unlock(&task->mutex);
            return TPOOL_ERR_TIMEOUT;
        }
    }

    if (task->is_detached) {
        pthread_mutex_unlock(&task->mutex);
        return TPOOL_ERR_TASK_NOT_PUSHED;
    }

    if (result) {
        *result = task->result;
    }

    pthread_mutex_unlock(&task->mutex);
    return 0;
}
#endif

int
thread_task_delete(struct thread_task *task)
{
    pthread_mutex_lock(&task->mutex);
    if (task->is_pushed || task->is_running) {
        pthread_mutex_unlock(&task->mutex);
        return TPOOL_ERR_TASK_IN_POOL;
    }
    if (task->is_detached) {
        pthread_mutex_unlock(&task->mutex);
        return TPOOL_ERR_TASK_NOT_PUSHED;
    }
    pthread_mutex_unlock(&task->mutex);

    pthread_mutex_destroy(&task->mutex);
    pthread_cond_destroy(&task->cond);
    free(task);
    return 0;
}

#if NEED_DETACH
int
thread_task_detach(struct thread_task *task)
{
    pthread_mutex_lock(&task->mutex);
    if (!task->is_pushed && !task->is_running && !task->is_finished) {
        pthread_mutex_unlock(&task->mutex);
        return TPOOL_ERR_TASK_NOT_PUSHED;
    }

    if (task->is_finished) {
        pthread_mutex_destroy(&task->mutex);
        pthread_cond_destroy(&task->cond);
        free(task);
        return 0;
    }

    task->is_detached = true;
    pthread_mutex_unlock(&task->mutex);
    return 0;
}
#endif
