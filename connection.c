/*
 * Some sort of Copyright
 */

#include <string.h>
#include <uk/sched.h>
#include <uk/thread.h>
#include "connection.h"
#include "ring.h"
#include "signal.h"

/* TODO: study memory layout and alignment of this and other shared structures*/
struct conn {
	struct conn_id id;
	unsigned long waiting_recv[2];
	unsigned long waiting_send[2];
	char closing;
	struct unimsg_ring rings[];
};

static struct unimsg_ring *pool;
static struct conn *conns;
static unsigned long conn_sz;
static unsigned long queue_sz;

int conn_init(struct unimsg_shm_header *shmh)
{
	UK_ASSERT(shmh);

	pool = (void *)shmh + shmh->conn_pool_off;
	conns = (void *)shmh + shmh->conn_conns_off;
	conn_sz = shmh->conn_sz;
	queue_sz = shmh->conn_queue_sz;

	return 0;
}

unsigned conn_get_idx(struct conn *c)
{
	UK_ASSERT(c);

	return ((void *)c - (void *)conns) / conn_sz;
}

struct conn *conn_from_idx(unsigned idx)
{
	UK_ASSERT(idx < pool->size);

	return (void *)conns + conn_sz * idx;
}

struct conn_id conn_get_id(struct conn *c)
{
	UK_ASSERT(c);

	return c->id;
}

int conn_alloc(struct conn **c, struct conn_id *id)
{
	UK_ASSERT(c && id);

	unsigned idx;
	if (unimsg_ring_dequeue(pool, &idx, 1))
		return -ENOMEM;

	*c = conn_from_idx(idx);
	(*c)->id = *id;

	return 0;
}

static struct unimsg_ring *get_ring(struct conn *c, unsigned dir)
{
	return (void *)c->rings + dir * queue_sz;
}

static void drain_ring(struct unimsg_ring *r)
{
	struct unimsg_shm_desc desc;

	while (!unimsg_ring_dequeue(r, &desc, 1))
		unimsg_buffer_put_internal(&desc, 1);

	unimsg_ring_reset(r);
}

void conn_free(struct conn *c)
{
	UK_ASSERT(c);

	drain_ring(get_ring(c, 0));
	drain_ring(get_ring(c, 1));

	c->id = (struct conn_id){0};
	c->waiting_recv[0] = 0;
	c->waiting_recv[1] = 0;
	c->waiting_send[0] = 0;
	c->waiting_send[1] = 0;
	c->closing = 0;

	unsigned idx = conn_get_idx(c);
	unimsg_ring_enqueue(pool, &idx, 1);
}

void conn_close(struct conn *c, enum conn_side side)
{
	UK_ASSERT(c);

	/* Flag the socket as closing, if it already was we need to free it,
	 * otherwise me might need to wake a waiting recv
	 */
	char expected = 0;
	if (__atomic_compare_exchange_n(&c->closing, &expected, 1, 0,
					__ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
		unsigned peer_id = side == CONN_SIDE_CLI ?
				   c->id.server_id : c->id.client_id;

		/* Wake potental waiting recv */
		unsigned long to_wake = ukarch_load_n(&c->waiting_recv[side]);
		if (to_wake)
			signal_send(peer_id, (struct signal *)&to_wake);

		/* Wake potental waiting send */
		to_wake = ukarch_load_n(&c->waiting_send[side ^ 1]);
		if (to_wake)
			signal_send(peer_id, (struct signal *)&to_wake);

	} else {
		conn_free(c);
	}
}

int conn_send(struct conn *c, struct unimsg_shm_desc *descs, unsigned ndescs,
	      enum conn_side side, int nonblock)
{
	UK_ASSERT(c && descs && ndescs > 0);

	if (c->closing)
		return -ECONNRESET;

	int queue = side;
	struct unimsg_ring *r = get_ring(c, queue);

	/* The loop handles spurious wakeups. TODO: can they happen? */
	while (unimsg_ring_enqueue(r, descs, ndescs)) {
		if (nonblock)
			return -EAGAIN;

		struct uk_thread *t = uk_thread_current();
		uk_thread_block(t);
		__atomic_store_n(&c->waiting_send[queue], t, __ATOMIC_SEQ_CST /*__ATOMIC_RELEASE*/);

		if (!unimsg_ring_enqueue(r, descs, ndescs)) {
			__atomic_store_n(&c->waiting_send[queue], NULL,
					 __ATOMIC_SEQ_CST /*__ATOMIC_RELEASE*/);
			uk_thread_wake(t);
			break;
		}
		if (ukarch_load_n(&c->closing)) {
			__atomic_store_n(&c->waiting_send[queue], NULL,
					 __ATOMIC_SEQ_CST /*__ATOMIC_RELEASE*/);
			uk_thread_wake(t);
			return -ECONNRESET;
		}

		uk_sched_yield();
	}

	unsigned long to_wake = __atomic_load_n(&c->waiting_recv[queue],
						__ATOMIC_SEQ_CST /*__ATOMIC_ACQUIRE*/);
	if (to_wake) {
		__atomic_store_n(&c->waiting_recv[queue], NULL,
				 __ATOMIC_SEQ_CST /*__ATOMIC_RELEASE*/);
		signal_send(side == CONN_SIDE_CLI ?
			    c->id.server_id : c->id.client_id,
			    (struct signal *)&to_wake);
	}

	return 0;
}

static unsigned dequeue_burst(struct unimsg_ring *r,
			      struct unimsg_shm_desc *descs, unsigned n)
{
	unsigned dequeued = 0;
	while (dequeued < n) {
		if (unimsg_ring_dequeue(r, &descs[dequeued], 1))
			return dequeued;
		dequeued++;
	}

	return dequeued;
}

int conn_recv(struct conn *c, struct unimsg_shm_desc *descs, unsigned *ndescs,
	      enum conn_side side, int nonblock)
{
	UK_ASSERT(c && descs && ndescs && *ndescs > 0);

	/* Flip the direction on the recv side */
	int queue = side ^ 1;
	struct unimsg_ring *r = get_ring(c, queue);
	unsigned dequeued = 0;

	/* The loop handles spurious wakeups. TODO: can they happen? */
	while ((dequeued = dequeue_burst(r, descs, *ndescs)) == 0) {
		if (c->closing)
			return -ECONNRESET;
		if (nonblock)
			return -EAGAIN;

		struct uk_thread *t = uk_thread_current();
		uk_thread_block(t);
		__atomic_store_n(&c->waiting_recv[queue], t, __ATOMIC_SEQ_CST /*__ATOMIC_RELEASE*/);

		if ((dequeued = dequeue_burst(r, descs, *ndescs)) > 0) {
			__atomic_store_n(&c->waiting_recv[queue], NULL,
					 __ATOMIC_SEQ_CST /*__ATOMIC_RELEASE*/);
			uk_thread_wake(t);
			break;
		}
		if (ukarch_load_n(&c->closing)) {
			__atomic_store_n(&c->waiting_recv[queue], NULL,
					 __ATOMIC_SEQ_CST /*__ATOMIC_RELEASE*/);
			uk_thread_wake(t);
			return -ECONNRESET;
		}

		uk_sched_yield();
	}

	unsigned long to_wake = __atomic_load_n(&c->waiting_send[queue],
						__ATOMIC_SEQ_CST /*__ATOMIC_ACQUIRE*/);
	if (to_wake) {
		__atomic_store_n(&c->waiting_send[queue], NULL,
				 __ATOMIC_SEQ_CST /*__ATOMIC_RELEASE*/);
		signal_send(side == CONN_SIDE_CLI ?
			    c->id.server_id : c->id.client_id,
			    (struct signal *)&to_wake);
	}

	*ndescs = dequeued;

	return 0;
}

int conn_poll_check(struct conn *c, enum conn_side side)
{
	UK_ASSERT(c);

	return unimsg_ring_count(get_ring(c, side ^ 1)) > 0 || c->closing;
}

int conn_poll_set(struct conn *c, enum conn_side side)
{
	UK_ASSERT(c);

	struct uk_thread *t = uk_thread_current();
	__atomic_store_n(&c->waiting_recv[side ^ 1], t, __ATOMIC_SEQ_CST);

	return unimsg_ring_count(get_ring(c, side ^ 1)) > 0 || c->closing;
}

int conn_poll_clean(struct conn *c, enum conn_side side)
{
	UK_ASSERT(c);

	__atomic_store_n(&c->waiting_recv[side ^ 1], NULL, __ATOMIC_SEQ_CST);

	return unimsg_ring_count(get_ring(c, side ^ 1)) > 0 || c->closing;
}