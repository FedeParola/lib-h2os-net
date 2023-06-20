/*
 * Some sort of Copyright
 */

#include <string.h>
#include <uk/preempt.h>
#include <uk/sched.h>
#include <uk/thread.h>
#include "conn_sock.h"
#include "ring.h"
#include "signal.h"

/* TODO: study memory layout and alignment of this and other shared structures*/
struct conn_sock {
	struct conn_sock_id id;
	unsigned long waiting_recv[2];
	unsigned long waiting_send[2];
	char closing;
	struct h2os_ring rings[];
};

static struct h2os_ring *pool;
static struct conn_sock *socks;
static unsigned long sock_sz;
static unsigned long queue_sz;

int conn_sock_init(struct h2os_shm_header *shmh)
{
	UK_ASSERT(shmh);

	pool = (void *)shmh + shmh->conn_sock_pool_off;
	socks = (void *)shmh + shmh->conn_sock_socks_off;
	sock_sz = shmh->conn_sock_sz;
	queue_sz = shmh->conn_queue_sz;

	return 0;
}

unsigned conn_sock_get_idx(struct conn_sock *s)
{
	UK_ASSERT(s);

	return ((void *)s - (void *)socks) / sock_sz;
}

struct conn_sock *conn_sock_from_idx(unsigned idx)
{
	UK_ASSERT(idx < pool->size);

	return (void *)socks + sock_sz * idx;
}

struct conn_sock_id conn_sock_get_id(struct conn_sock *s)
{
	UK_ASSERT(s);

	return s->id;
}

int conn_sock_alloc(struct conn_sock **s, struct conn_sock_id *id)
{
	UK_ASSERT(s && id);

	unsigned idx;
	if (h2os_ring_dequeue(pool, &idx, 1))
		return -ENOMEM;

	*s = conn_sock_from_idx(idx);
	(*s)->id = *id;

	return 0;
}

static struct h2os_ring *get_ring(struct conn_sock *s, unsigned dir)
{
	return (void *)s->rings + dir * queue_sz;
}

void conn_sock_free(struct conn_sock *s)
{
	UK_ASSERT(s);

	s->id = (struct conn_sock_id){0};
	s->waiting_recv[0] = 0;
	s->waiting_recv[1] = 0;
	s->waiting_send[0] = 0;
	s->waiting_send[1] = 0;
	s->closing = 0;
	h2os_ring_reset(get_ring(s, 0));
	h2os_ring_reset(get_ring(s, 1));

	unsigned idx = conn_sock_get_idx(s);
	h2os_ring_enqueue(pool, &idx, 1);
}

void conn_sock_close(struct conn_sock *s, enum conn_sock_dir dir)
{
	UK_ASSERT(s);

	/* Flag the socket as closing, if it already was we need to free it,
	 * otherwise me might need to wake a waiting recv
	 */
	char expected = 0;
	if (__atomic_compare_exchange_n(&s->closing, &expected, 1, 0,
					__ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
		unsigned peer_id = dir == DIR_CLI_TO_SRV ?
				   s->id.server_addr : s->id.client_addr;

		/* Wake potental waiting recv */
		unsigned long to_wake = ukarch_load_n(&s->waiting_recv[dir]);
		if (to_wake)
			signal_send(peer_id, (struct signal *)&to_wake);

		/* Wake potental waiting send */
		to_wake = ukarch_load_n(&s->waiting_send[dir ^ 1]);
		if (to_wake)
			signal_send(peer_id, (struct signal *)&to_wake);

	} else {
		conn_sock_free(s);
	}
}

int conn_sock_send(struct conn_sock *s, struct h2os_shm_desc *desc,
		   enum conn_sock_dir dir, int nonblock)
{
	UK_ASSERT(s && desc);

	if (s->closing)
		return -ECONNRESET;

	int queue = dir;
	struct h2os_ring *r = get_ring(s, queue);

	/* The loop handles spurious wakeups. TODO: can they happen? */
	while (h2os_ring_enqueue(r, desc, 1)) {
		if (nonblock)
			return -EAGAIN;

		struct uk_thread *t = uk_thread_current();
		uk_preempt_disable();
		uk_thread_block(t);
		__atomic_store_n(&s->waiting_send[queue], t, __ATOMIC_RELEASE);

		if (!h2os_ring_enqueue(r, desc, 1)) {
			__atomic_store_n(&s->waiting_send[queue], NULL,
					 __ATOMIC_RELEASE);
			uk_thread_wake(t);
			uk_preempt_enable();
			break;
		}
		if (ukarch_load_n(&s->closing)) {
			__atomic_store_n(&s->waiting_send[queue], NULL,
					 __ATOMIC_RELEASE);
			uk_thread_wake(t);
			uk_preempt_enable();
			return -ECONNRESET;
		}

		uk_preempt_enable();
		uk_sched_yield();
	}

	unsigned long to_wake = __atomic_load_n(&s->waiting_recv[queue],
						__ATOMIC_ACQUIRE);
	if (to_wake) {
		__atomic_store_n(&s->waiting_recv[queue], NULL,
				 __ATOMIC_RELEASE);
		signal_send(dir == DIR_CLI_TO_SRV ? s->id.server_addr
				    : s->id.client_addr,
				    (struct signal *)&to_wake);
	}

	return 0;
}

int conn_sock_recv(struct conn_sock *s, struct h2os_shm_desc *desc,
		   enum conn_sock_dir dir, int nonblock)
{
	UK_ASSERT(s && desc);

	/* Flip the direction on the recv side */
	int queue = dir ^ 1;
	struct h2os_ring *r = get_ring(s, queue);

	/* The loop handles spurious wakeups. TODO: can they happen? */
	while (h2os_ring_dequeue(r, desc, 1)) {
		if (s->closing)
			return -ECONNRESET;
		if (nonblock)
			return -EAGAIN;

		struct uk_thread *t = uk_thread_current();
		uk_preempt_disable();
		uk_thread_block(t);
		__atomic_store_n(&s->waiting_recv[queue], t, __ATOMIC_RELEASE);

		if (!h2os_ring_dequeue(r, desc, 1)) {
			__atomic_store_n(&s->waiting_recv[queue], NULL,
					 __ATOMIC_RELEASE);
			uk_thread_wake(t);
			uk_preempt_enable();
			break;
		}
		if (ukarch_load_n(&s->closing)) {
			__atomic_store_n(&s->waiting_recv[queue], NULL,
					 __ATOMIC_RELEASE);
			uk_thread_wake(t);
			uk_preempt_enable();
			return -ECONNRESET;
		}

		uk_preempt_enable();
		uk_sched_yield();
	}

	unsigned long to_wake = __atomic_load_n(&s->waiting_send[queue],
						__ATOMIC_ACQUIRE);
	if (to_wake) {
		__atomic_store_n(&s->waiting_send[queue], NULL,
				 __ATOMIC_RELEASE);
		signal_send(dir == DIR_CLI_TO_SRV ? s->id.server_addr
				    : s->id.client_addr,
				    (struct signal *)&to_wake);
	}

	return 0;
}