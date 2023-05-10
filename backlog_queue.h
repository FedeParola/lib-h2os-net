/*
 * Some sort of Copyright
 */

#ifndef __LIBH2OS_BACKLOG_QUEUE__
#define __LIBH2OS_BACKLOG_QUEUE__

#include <uk/arch/atomic.h>

#define BACKLOG_QUEUE_SIZE 128
#define MASK (BACKLOG_QUEUE_SIZE - 1)

struct backlog_queue {
        unsigned items[BACKLOG_QUEUE_SIZE];
	unsigned cons;
	unsigned prod;
        unsigned count;
        unsigned char available[BACKLOG_QUEUE_SIZE];
};

static inline
int backlog_queue_produce(struct backlog_queue *q, unsigned item,
			  int *was_empty)
{
        unsigned count = ukarch_fetch_add(&q->count, 1);
	if (count == BACKLOG_QUEUE_SIZE) {
		ukarch_fetch_add(&q->count, -1);
		return -EAGAIN;
	}

	unsigned to_write = ukarch_fetch_add(&q->prod, 1);
	q->items[to_write & MASK] = item;
	ukarch_store_n(&q->available[to_write & MASK], 1);

	*was_empty = count == 0;

	return 0;
}

static inline
int backlog_queue_consume(struct backlog_queue *q, unsigned *item)
{
        if (!ukarch_load_n(&q->available[q->cons & MASK]))
		return -EAGAIN;

	*item = q->items[q->cons & MASK];
	ukarch_store_n(&q->available[q->cons & MASK], 0);
	q->cons++;
	ukarch_fetch_add(&q->count, -1);

	return 0;
}

/**
 * Removes one element from the queue without preserving its correctness. This
 * method must only be called with exclusive access to the queue and after the
 * operation only other calls to this method are allowed and the queue must be
 * re-initilized.
*/
static inline
int backlog_queue_drain_one(struct backlog_queue *q, unsigned *item)
{
	if (q->count == 0)
		return -ENOENT;

	*item = q->items[q->cons++ & MASK];
	q->count--;

	return 0;
}

#undef MASK

#endif /* __LIBH2OS_BACKLOG_QUEUE__ */