/*
 * Some sort of Copyright
 */

#include <string.h>
#include <uk/preempt.h>
#include <uk/sched.h>
#include <uk/thread.h>
#include "conn_sock.h"
#include "idxpool.h"
#include "signal.h"
#include "sock_queue.h"

/* TODO: study memory layout and alignment of this and other shared structures*/
struct conn_sock {
	idxpool_token_t token;
	struct conn_sock_id id;
	struct sock_queue qs[2];
	unsigned long waiting_recv[2];
	unsigned long waiting_send[2];
	char closing;
};

static struct idxpool *pool;
static struct conn_sock *socks;

int conn_sock_init(struct h2os_shm_header *shmh)
{
	UK_ASSERT(shmh);

	pool = (void *)shmh + shmh->conn_sock_off;
	socks = (struct conn_sock *)(pool->nodes + pool->size);

	return 0;
}

unsigned conn_sock_get_idx(struct conn_sock *s)
{
	UK_ASSERT(s);

	return s - socks;
}

struct conn_sock *conn_sock_from_idx(unsigned idx)
{
	UK_ASSERT(idx < pool->size);

	return &socks[idx];
}

struct conn_sock_id conn_sock_get_id(struct conn_sock *s)
{
	UK_ASSERT(s);

	return s->id;
}

int conn_sock_alloc(struct conn_sock **s, struct conn_sock_id *id)
{
	UK_ASSERT(s && id);

	idxpool_token_t t;
	if (idxpool_get(pool, &t))
		return -ENOMEM;

	(*s) = &socks[idxpool_get_idx(t)];
	(*s)->token = t;
	(*s)->id = *id;

	return 0;
}

void conn_sock_free(struct conn_sock *s)
{
	UK_ASSERT(s);

	idxpool_token_t t = s->token;
	memset(s, 0, sizeof(*s));
	idxpool_put(pool, t);
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

	int was_empty;
	int queue = dir;

	/* The loop handles spurious wakeups. TODO: can they happen? */
	while (sock_queue_produce(&s->qs[queue], desc, &was_empty)) {
		if (nonblock)
			return -EAGAIN;

		struct uk_thread *t = uk_thread_current();
		uk_preempt_disable();
		uk_thread_block(t);
		ukarch_store_n(&s->waiting_send[queue], t);

		if (!sock_queue_produce(&s->qs[queue], desc, &was_empty)) {
			ukarch_store_n(&s->waiting_send[queue], NULL);
			uk_thread_wake(t);
			uk_preempt_enable();
			break;
		}
		if (ukarch_load_n(&s->closing)) {
			ukarch_store_n(&s->waiting_send[queue], NULL);
			uk_thread_wake(t);
			uk_preempt_enable();
			return -ECONNRESET;
		}

		uk_preempt_enable();
		uk_sched_yield();

		ukarch_store_n(&s->waiting_send[queue], NULL);
	}

	if (was_empty) {
		unsigned long to_wake = ukarch_load_n(&s->waiting_recv[queue]);
		if (to_wake) {
			ukarch_store_n(&s->waiting_recv[queue], NULL);
			signal_send(dir == DIR_CLI_TO_SRV ? s->id.server_addr
				    : s->id.client_addr,
				    (struct signal *)&to_wake);
		}
	}

	return 0;
}

int conn_sock_recv(struct conn_sock *s, struct h2os_shm_desc *desc,
		   enum conn_sock_dir dir, int nonblock)
{
	UK_ASSERT(s && desc);

	int was_full;
	/* Flip the direction on the recv side */
	int queue = dir ^ 1;

	/* The loop handles spurious wakeups. TODO: can they happen? */
	while (sock_queue_consume(&s->qs[queue], desc, &was_full)) {
		if (s->closing)
			return -ECONNRESET;
		if (nonblock)
			return -EAGAIN;

		struct uk_thread *t = uk_thread_current();
		uk_preempt_disable();
		uk_thread_block(t);
		ukarch_store_n(&s->waiting_recv[queue], t);

		if (!sock_queue_consume(&s->qs[queue], desc, &was_full)) {
			ukarch_store_n(&s->waiting_recv[queue], NULL);
			uk_thread_wake(t);
			uk_preempt_enable();
			break;
		}
		if (ukarch_load_n(&s->closing)) {
			ukarch_store_n(&s->waiting_recv[queue], NULL);
			uk_thread_wake(t);
			uk_preempt_enable();
			return -ECONNRESET;
		}

		uk_preempt_enable();
		uk_sched_yield();

		ukarch_store_n(&s->waiting_recv[queue], NULL);
	}

	if (was_full) {
		unsigned long to_wake = ukarch_load_n(&s->waiting_send[queue]);
		if (to_wake) {
			ukarch_store_n(&s->waiting_recv[queue], 0);
			signal_send(dir == DIR_CLI_TO_SRV ? s->id.server_addr
				    : s->id.client_addr,
				    (struct signal *)&to_wake);
		}
	}

	return 0;
}