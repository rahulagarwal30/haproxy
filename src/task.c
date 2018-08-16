/*
 * Task management functions.
 *
 * Copyright 2000-2009 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <string.h>

#include <common/config.h>
#include <common/memory.h>
#include <common/mini-clist.h>
#include <common/standard.h>
#include <common/time.h>
#include <eb32sctree.h>
#include <eb32tree.h>

#include <proto/proxy.h>
#include <proto/stream.h>
#include <proto/task.h>
#include <proto/fd.h>

struct pool_head *pool_head_task;
struct pool_head *pool_head_tasklet;

/* This is the memory pool containing all the signal structs. These
 * struct are used to store each requiered signal between two tasks.
 */
struct pool_head *pool_head_notification;

unsigned int nb_tasks = 0;
volatile unsigned long active_tasks_mask = 0; /* Mask of threads with active tasks */
volatile unsigned long global_tasks_mask = 0; /* Mask of threads with tasks in the global runqueue */
unsigned int tasks_run_queue = 0;
unsigned int tasks_run_queue_cur = 0;    /* copy of the run queue size */
unsigned int nb_tasks_cur = 0;     /* copy of the tasks count */
unsigned int niced_tasks = 0;      /* number of niced tasks in the run queue */

THREAD_LOCAL struct task *curr_task = NULL; /* task currently running or NULL */
THREAD_LOCAL struct eb32sc_node *rq_next = NULL; /* Next task to be potentially run */

struct list task_list[MAX_THREADS]; /* List of tasks to be run, mixing tasks and tasklets */
int task_list_size[MAX_THREADS]; /* Number of tasks in the task_list */

__decl_hathreads(HA_SPINLOCK_T __attribute__((aligned(64))) rq_lock); /* spin lock related to run queue */
__decl_hathreads(HA_SPINLOCK_T __attribute__((aligned(64))) wq_lock); /* spin lock related to wait queue */

static struct eb_root timers;      /* sorted timers tree */
#ifdef USE_THREAD
struct eb_root rqueue;      /* tree constituting the run queue */
int global_rqueue_size; /* Number of element sin the global runqueue */
#endif
struct eb_root rqueue_local[MAX_THREADS]; /* tree constituting the per-thread run queue */
int rqueue_size[MAX_THREADS]; /* Number of elements in the per-thread run queue */
static unsigned int rqueue_ticks;  /* insertion count */

/* Puts the task <t> in run queue at a position depending on t->nice. <t> is
 * returned. The nice value assigns boosts in 32th of the run queue size. A
 * nice value of -1024 sets the task to -tasks_run_queue*32, while a nice value
 * of 1024 sets the task to tasks_run_queue*32. The state flags are cleared, so
 * the caller will have to set its flags after this call.
 * The task must not already be in the run queue. If unsure, use the safer
 * task_wakeup() function.
 */
void __task_wakeup(struct task *t, struct eb_root *root)
{
	void *expected = NULL;
	int *rq_size;
	unsigned long __maybe_unused old_active_mask;

#ifdef USE_THREAD
	if (root == &rqueue) {
		rq_size = &global_rqueue_size;
		HA_SPIN_LOCK(TASK_RQ_LOCK, &rq_lock);
	} else
#endif
	{
		int nb = root - &rqueue_local[0];
		rq_size = &rqueue_size[nb];
	}
	/* Make sure if the task isn't in the runqueue, nobody inserts it
	 * in the meanwhile.
	 */
redo:
	if (unlikely(!HA_ATOMIC_CAS(&t->rq.node.leaf_p, &expected, (void *)0x1))) {
#ifdef USE_THREAD
		if (root == &rqueue)
			HA_SPIN_UNLOCK(TASK_RQ_LOCK, &rq_lock);
#endif
		return;
	}
	/* There's a small race condition, when running a task, the thread
	 * first sets TASK_RUNNING, and then unlink the task.
	 * If an another thread calls task_wakeup() for the same task,
	 * it may set t->state before TASK_RUNNING was set, and then try
	 * to set t->rq.nod.leaf_p after it was unlinked.
	 * To make sure it is not a problem, we check if TASK_RUNNING is set
	 * again. If it is, we unset t->rq.node.leaf_p.
	 * We then check for TASK_RUNNING a third time. If it is still there,
	 * then we can give up, the task will be re-queued later if it needs
	 * to be. If it's not there, and there is still something in t->state,
	 * then we have to requeue.
	 */
	if (((volatile unsigned short)(t->state)) & TASK_RUNNING) {
		unsigned short state;
		t->rq.node.leaf_p = NULL;
		__ha_barrier_store();

		state = (volatile unsigned short)(t->state);
		if (unlikely(state != 0 && !(state & TASK_RUNNING)))
			goto redo;
#ifdef USE_THREAD
		if (root == &rqueue)
			HA_SPIN_UNLOCK(TASK_RQ_LOCK, &rq_lock);
#endif
		return;
	}
	HA_ATOMIC_ADD(&tasks_run_queue, 1);
#ifdef USE_THREAD
	if (root == &rqueue) {
		HA_ATOMIC_OR(&global_tasks_mask, t->thread_mask);
		__ha_barrier_store();
	}
#endif
	old_active_mask = active_tasks_mask;
	HA_ATOMIC_OR(&active_tasks_mask, t->thread_mask);
	t->rq.key = HA_ATOMIC_ADD(&rqueue_ticks, 1);

	if (likely(t->nice)) {
		int offset;

		HA_ATOMIC_ADD(&niced_tasks, 1);
		if (likely(t->nice > 0))
			offset = (unsigned)((*rq_size * (unsigned int)t->nice) / 32U);
		else
			offset = -(unsigned)((*rq_size * (unsigned int)-t->nice) / 32U);
		t->rq.key += offset;
	}

	eb32sc_insert(root, &t->rq, t->thread_mask);
#ifdef USE_THREAD
	if (root == &rqueue) {
		global_rqueue_size++;
		HA_ATOMIC_OR(&t->state, TASK_GLOBAL);
		HA_SPIN_UNLOCK(TASK_RQ_LOCK, &rq_lock);
	} else
#endif
	{
		int nb = root - &rqueue_local[0];

		rqueue_size[nb]++;
	}
#ifdef USE_THREAD
	/* If all threads that are supposed to handle this task are sleeping,
	 * wake one.
	 */
	if ((((t->thread_mask & all_threads_mask) & sleeping_thread_mask) ==
	    (t->thread_mask & all_threads_mask)) &&
	    !(t->thread_mask & old_active_mask))
		wake_thread(my_ffsl((t->thread_mask & all_threads_mask) &~ tid_bit) - 1);
#endif
	return;
}

/*
 * __task_queue()
 *
 * Inserts a task into the wait queue at the position given by its expiration
 * date. It does not matter if the task was already in the wait queue or not,
 * as it will be unlinked. The task must not have an infinite expiration timer.
 * Last, tasks must not be queued further than the end of the tree, which is
 * between <now_ms> and <now_ms> + 2^31 ms (now+24days in 32bit).
 *
 * This function should not be used directly, it is meant to be called by the
 * inline version of task_queue() which performs a few cheap preliminary tests
 * before deciding to call __task_queue().
 */
void __task_queue(struct task *task)
{
	if (likely(task_in_wq(task)))
		__task_unlink_wq(task);

	/* the task is not in the queue now */
	task->wq.key = task->expire;
#ifdef DEBUG_CHECK_INVALID_EXPIRATION_DATES
	if (tick_is_lt(task->wq.key, now_ms))
		/* we're queuing too far away or in the past (most likely) */
		return;
#endif

	eb32_insert(&timers, &task->wq);

	return;
}

/*
 * Extract all expired timers from the timer queue, and wakes up all
 * associated tasks. Returns the date of next event (or eternity).
 */
int wake_expired_tasks()
{
	struct task *task;
	struct eb32_node *eb;
	int ret = TICK_ETERNITY;

	while (1) {
		HA_SPIN_LOCK(TASK_WQ_LOCK, &wq_lock);
  lookup_next:
		eb = eb32_lookup_ge(&timers, now_ms - TIMER_LOOK_BACK);
		if (!eb) {
			/* we might have reached the end of the tree, typically because
			* <now_ms> is in the first half and we're first scanning the last
			* half. Let's loop back to the beginning of the tree now.
			*/
			eb = eb32_first(&timers);
			if (likely(!eb))
				break;
		}

		if (tick_is_lt(now_ms, eb->key)) {
			/* timer not expired yet, revisit it later */
			ret = eb->key;
			break;
		}

		/* timer looks expired, detach it from the queue */
		task = eb32_entry(eb, struct task, wq);
		__task_unlink_wq(task);

		/* It is possible that this task was left at an earlier place in the
		 * tree because a recent call to task_queue() has not moved it. This
		 * happens when the new expiration date is later than the old one.
		 * Since it is very unlikely that we reach a timeout anyway, it's a
		 * lot cheaper to proceed like this because we almost never update
		 * the tree. We may also find disabled expiration dates there. Since
		 * we have detached the task from the tree, we simply call task_queue
		 * to take care of this. Note that we might occasionally requeue it at
		 * the same place, before <eb>, so we have to check if this happens,
		 * and adjust <eb>, otherwise we may skip it which is not what we want.
		 * We may also not requeue the task (and not point eb at it) if its
		 * expiration time is not set.
		 */
		if (!tick_is_expired(task->expire, now_ms)) {
			if (tick_isset(task->expire))
				__task_queue(task);
			goto lookup_next;
		}
		task_wakeup(task, TASK_WOKEN_TIMER);
		HA_SPIN_UNLOCK(TASK_WQ_LOCK, &wq_lock);
	}

	HA_SPIN_UNLOCK(TASK_WQ_LOCK, &wq_lock);
	return ret;
}

/* The run queue is chronologically sorted in a tree. An insertion counter is
 * used to assign a position to each task. This counter may be combined with
 * other variables (eg: nice value) to set the final position in the tree. The
 * counter may wrap without a problem, of course. We then limit the number of
 * tasks processed to 200 in any case, so that general latency remains low and
 * so that task positions have a chance to be considered.
 *
 * The function adjusts <next> if a new event is closer.
 */
void process_runnable_tasks()
{
	struct task *t;
	int max_processed;

	tasks_run_queue_cur = tasks_run_queue; /* keep a copy for reporting */
	nb_tasks_cur = nb_tasks;
	max_processed = global.tune.runqueue_depth;

	if (likely(global.nbthread > 1)) {
		HA_SPIN_LOCK(TASK_RQ_LOCK, &rq_lock);
		if (!(active_tasks_mask & tid_bit)) {
			HA_SPIN_UNLOCK(TASK_RQ_LOCK, &rq_lock);
			activity[tid].empty_rq++;
			return;
		}

#ifdef USE_THREAD
		/* Get some elements from the global run queue and put it in the
		 * local run queue. To try to keep a bit of fairness, just get as
		 * much elements from the global list as to have a bigger local queue
		 * than the average.
		 */
		while ((task_list_size[tid] + rqueue_size[tid]) * global.nbthread <= tasks_run_queue) {
			/* we have to restart looking up after every batch */
			rq_next = eb32sc_lookup_ge(&rqueue, rqueue_ticks - TIMER_LOOK_BACK, tid_bit);
			if (unlikely(!rq_next)) {
				/* either we just started or we reached the end
				 * of the tree, typically because <rqueue_ticks>
				 * is in the first half and we're first scanning
				 * the last half. Let's loop back to the beginning
				 * of the tree now.
				 */
				rq_next = eb32sc_first(&rqueue, tid_bit);
				if (!rq_next) {
					HA_ATOMIC_AND(&global_tasks_mask, ~tid_bit);
					break;
				}
			}

			t = eb32sc_entry(rq_next, struct task, rq);
			rq_next = eb32sc_next(rq_next, tid_bit);

			/* detach the task from the queue */
			__task_unlink_rq(t);
			__task_wakeup(t, &rqueue_local[tid]);
		}
#endif

		HA_SPIN_UNLOCK(TASK_RQ_LOCK, &rq_lock);
	} else {
		if (!(active_tasks_mask & tid_bit)) {
			activity[tid].empty_rq++;
			return;
		}
	}
	/* Get some tasks from the run queue, make sure we don't
	 * get too much in the task list, but put a bit more than
	 * the max that will be run, to give a bit more fairness
	 */
	while (max_processed + (max_processed / 10) > task_list_size[tid]) {
		/* Note: this loop is one of the fastest code path in
		 * the whole program. It should not be re-arranged
		 * without a good reason.
		 */

		/* we have to restart looking up after every batch */
		rq_next = eb32sc_lookup_ge(&rqueue_local[tid], rqueue_ticks - TIMER_LOOK_BACK, tid_bit);
		if (unlikely(!rq_next)) {
			/* either we just started or we reached the end
			 * of the tree, typically because <rqueue_ticks>
			 * is in the first half and we're first scanning
			 * the last half. Let's loop back to the beginning
			 * of the tree now.
			 */
			rq_next = eb32sc_first(&rqueue_local[tid], tid_bit);
			if (!rq_next)
				break;
		}
		t = eb32sc_entry(rq_next, struct task, rq);
		rq_next = eb32sc_next(rq_next, tid_bit);
		/* Make sure nobody re-adds the task in the runqueue */
		HA_ATOMIC_OR(&t->state, TASK_RUNNING);

		/* detach the task from the queue */
		__task_unlink_rq(t);
		/* And add it to the local task list */
		task_insert_into_tasklet_list(t);
	}
	if (!(global_tasks_mask & tid_bit) && rqueue_size[tid] == 0) {
		HA_ATOMIC_AND(&active_tasks_mask, ~tid_bit);
		__ha_barrier_load();
		if (global_tasks_mask & tid_bit)
			HA_ATOMIC_OR(&active_tasks_mask, tid_bit);
	}
	while (max_processed > 0 && !LIST_ISEMPTY(&task_list[tid])) {
		struct task *t;
		unsigned short state;
		void *ctx;
		struct task *(*process)(struct task *t, void *ctx, unsigned short state);

		t = (struct task *)LIST_ELEM(task_list[tid].n, struct tasklet *, list);
		state = HA_ATOMIC_XCHG(&t->state, TASK_RUNNING);
		__ha_barrier_store();
		task_remove_from_task_list(t);

		ctx = t->context;
		process = t->process;
		t->calls++;
		curr_task = (struct task *)t;
		if (likely(process == process_stream))
			t = process_stream(t, ctx, state);
		else {
			if (t->process != NULL)
				t = process(TASK_IS_TASKLET(t) ? NULL : t, ctx, state);
			else {
				__task_free(t);
				t = NULL;
			}
		}
		curr_task = NULL;
		/* If there is a pending state  we have to wake up the task
		 * immediatly, else we defer it into wait queue
		 */
		if (t != NULL) {
			state = HA_ATOMIC_AND(&t->state, ~TASK_RUNNING);
			if (state)
#ifdef USE_THREAD
				__task_wakeup(t, (t->thread_mask == tid_bit ||
				    global.nbthread == 1) ?
				    &rqueue_local[tid] : &rqueue);
#else
				__task_wakeup(t, &rqueue_local[tid]);
#endif
			else
				task_queue(t);
		}

		max_processed--;
		if (max_processed <= 0) {
			HA_ATOMIC_OR(&active_tasks_mask, tid_bit);
			activity[tid].long_rq++;
			break;
		}
	}
}

/* perform minimal intializations, report 0 in case of error, 1 if OK. */
int init_task()
{
	int i;

	memset(&timers, 0, sizeof(timers));
#ifdef USE_THREAD
	memset(&rqueue, 0, sizeof(rqueue));
#endif
	HA_SPIN_INIT(&wq_lock);
	HA_SPIN_INIT(&rq_lock);
	for (i = 0; i < MAX_THREADS; i++) {
		memset(&rqueue_local[i], 0, sizeof(rqueue_local[i]));
		LIST_INIT(&task_list[i]);
		task_list_size[i] = 0;
	}
	pool_head_task = create_pool("task", sizeof(struct task), MEM_F_SHARED);
	if (!pool_head_task)
		return 0;
	pool_head_tasklet = create_pool("tasklet", sizeof(struct tasklet), MEM_F_SHARED);
	if (!pool_head_tasklet)
		return 0;
	pool_head_notification = create_pool("notification", sizeof(struct notification), MEM_F_SHARED);
	if (!pool_head_notification)
		return 0;
	return 1;
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
