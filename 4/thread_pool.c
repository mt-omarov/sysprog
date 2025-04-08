#include "thread_pool.h"
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>

struct thread_task {
	thread_task_f function;
	void *arg;
    void *result;

    bool is_running;
    bool is_finished;
    bool is_pushed;

    pthread_mutex_t mutex;
    pthread_cond_t cond;

    struct thread_task *next;
    struct thread_task *prev;
};

struct thread_pool {
	pthread_t *threads;

    int max_thread_count;
    int thread_count;

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
	if (!*pool) return TPOOL_ERR_INVALID_ARGUMENT;

	(*pool)->max_thread_count = max_thread_count;
	(*pool)->thread_count = 0;
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

	if (pool->task_head != NULL) {
		pthread_mutex_unlock(&pool->mutex);
		return TPOOL_ERR_HAS_TASKS;
	}

	pool->is_shutdown = true;
	pthread_cond_broadcast(&pool->cond);
	pthread_mutex_unlock(&pool->mutex);

	for (int i = 0; i < pool->thread_count; ++i) {
		pthread_join(pool->threads[i], NULL);
	}

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

    printf("\tpush_task(): before updating pool->task_head and tail\n");

	task->is_pushed = true;
	task->next = NULL;

	if (pool->task_head) {
        pool->task_head->prev = task;
        task->next = pool->task_head;
    } {
        pool->task_tail = task;
        task->next = NULL;
    }

    pool->task_head = task;
    task->prev = NULL;

    printf("\tpush_task(): after updating pool->task_head and tail\n");
    printf("\tpush_task(): before checking pool->thread_count\n");

	if (pool->thread_count < pool->max_thread_count) {
        printf("\tpush_task(): pool->thread_count is good, now calling pthread_create()\n");
		pthread_create(&pool->threads[pool->thread_count++], NULL, worker_thread, pool);
        printf("\tpush_task(): called pthread_create()\n");
	}

	pthread_cond_signal(&pool->cond);
	pthread_mutex_unlock(&pool->mutex);
    printf("\tpush_task(): end\n");
	return 0;
}

int
thread_task_new(struct thread_task **task, thread_task_f function, void *arg)
{
    if (!task || !function) return TPOOL_ERR_INVALID_ARGUMENT;

    *task = malloc(sizeof(struct thread_task));
    if (!*task) return TPOOL_ERR_INVALID_ARGUMENT;

    (*task)->function = function;
    (*task)->arg = arg;
    (*task)->result = NULL;
    (*task)->is_running = false;
    (*task)->is_finished = false;
    (*task)->is_pushed = false;
    (*task)->next = NULL;
    (*task)->prev = NULL;
    pthread_mutex_init(&(*task)->mutex, NULL);
    pthread_cond_init(&(*task)->cond, NULL);
    return 0;
}

static void *
worker_thread(void *arg) {
    printf("\tworker(): start\n");
    struct thread_pool *pool = arg;

	while (true) {
		pthread_mutex_lock(&pool->mutex);

		while (!pool->task_head && !pool->is_shutdown) {
			pthread_cond_wait(&pool->cond, &pool->mutex);
		}

		if (pool->is_shutdown) {
			pthread_mutex_unlock(&pool->mutex);
			break;
		}

		struct thread_task *task = pool->task_head;
		if (task) {
			pool->task_head = task->next;

			if (!pool->task_head) {
				pool->task_tail = NULL;
            }
		}
		pthread_mutex_unlock(&pool->mutex);

        printf("\tworker(): after getting task and before calling function\n");
		if (task) {
			pthread_mutex_lock(&task->mutex);
			task->is_running = true;
			pthread_mutex_unlock(&task->mutex);

            printf("\tworker(): right before calling function\n");
			void *res = task->function(task->arg);
            printf("\tworker(): after calling function\n");

			pthread_mutex_lock(&task->mutex);
			task->result = res;
			task->is_finished = true;
			task->is_running = false;
			pthread_cond_broadcast(&task->cond);
			pthread_mutex_unlock(&task->mutex);
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

	if (!task->is_pushed) {
		pthread_mutex_unlock(&task->mutex);
		return TPOOL_ERR_TASK_NOT_PUSHED;
	}

	while (!task->is_finished) {
		pthread_cond_wait(&task->cond, &task->mutex);
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
	/* IMPLEMENT THIS FUNCTION */
	(void)task;
	(void)timeout;
	(void)result;
	return TPOOL_ERR_NOT_IMPLEMENTED;
}

#endif

int
thread_task_delete(struct thread_task *task)
{
	pthread_mutex_lock(&task->mutex);
	if (task->is_pushed && !task->is_finished) {
		pthread_mutex_unlock(&task->mutex);
		return TPOOL_ERR_TASK_IN_POOL;
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
	/* IMPLEMENT THIS FUNCTION */
	(void)task;
	return TPOOL_ERR_NOT_IMPLEMENTED;
}

#endif
