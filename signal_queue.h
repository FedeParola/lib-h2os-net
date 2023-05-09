/*
 * Some sort of Copyright
 */

#ifndef __LIBH2OS_SIGNAL_QUEUE__
#define __LIBH2OS_SIGNAL_QUEUE__

#include <uk/arch/atomic.h>

#define SIGNAL_QUEUE_SIZE 256
#define MASK (SIGNAL_QUEUE_SIZE - 1)

struct signal {
	unsigned long target_thread;
};

struct signal_queue {
        struct signal items[SIGNAL_QUEUE_SIZE];
	unsigned cons;
	unsigned prod;
        unsigned count;
        unsigned char available[SIGNAL_QUEUE_SIZE];
};

static inline
int signal_queue_produce(struct signal_queue *q, struct signal *item,
			 int *was_empty)
{
        unsigned count = ukarch_fetch_add(&q->count, 1);
	if (count == SIGNAL_QUEUE_SIZE) {
		ukarch_fetch_add(&q->count, -1);
		return -EAGAIN;
	}

	unsigned to_write = ukarch_fetch_add(&q->prod, 1);
	q->items[to_write & MASK] = *item;
	ukarch_store_n(&q->available[to_write & MASK], 1);

	*was_empty = count == 0;

	return 0;
}

static inline
int signal_queue_consume(struct signal_queue *q, struct signal *item)
{
        if (!ukarch_load_n(&q->available[q->cons & MASK]))
		return -EAGAIN;

	*item = q->items[q->cons & MASK];
	ukarch_store_n(&q->available[q->cons & MASK], 0);
	q->cons++;
	ukarch_fetch_add(&q->count, -1);

	return 0;
}

#undef MASK

#endif /* __LIBH2OS_SIGNAL_QUEUE__ */