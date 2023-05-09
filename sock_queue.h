/*
 * Some sort of Copyright
 */

#ifndef __LIBH2OS_SOCK_QUEUE__
#define __LIBH2OS_SOCK_QUEUE__

#include <h2os/shm.h>

#define SOCK_QUEUE_SIZE 256
#define MASK (SOCK_QUEUE_SIZE - 1)

struct sock_queue {
        struct h2os_shm_desc items[SOCK_QUEUE_SIZE];
	unsigned cons;
	unsigned prod;
};

static inline
int sock_queue_produce(struct sock_queue *q, struct h2os_shm_desc *item,
                       int *was_empty)
{
        unsigned cons = __atomic_load_n(&q->cons, __ATOMIC_ACQUIRE);
        if (q->prod - cons == SOCK_QUEUE_SIZE)
                return -EAGAIN;

	q->items[q->prod & MASK] = *item;
        *was_empty = q->prod == cons;
	__atomic_store_n(&q->prod, q->prod + 1, __ATOMIC_RELEASE);

	return 0;
}

static inline
int sock_queue_consume(struct sock_queue *q, struct h2os_shm_desc *item,
                       int *was_full)
{
        unsigned prod = __atomic_load_n(&q->prod, __ATOMIC_ACQUIRE);
        if (q->cons == prod)
                return -EAGAIN;

	*item = q->items[q->cons & MASK];
        *was_full = prod - q->cons == SOCK_QUEUE_SIZE;
	__atomic_store_n(&q->cons, q->cons + 1, __ATOMIC_RELEASE);

	return 0;
}

#undef MASK

#endif /* __LIBH2OS_SOCK_QUEUE__ */