/*
 * Some sort of Copyright
 */

#include <string.h>
#include <uk/preempt.h>
#include <uk/sched.h>
#include <uk/thread.h>
#include "conn_sock.h"
#include "signal.h"
#include "sock_queue.h"

#define H2OS_MAX_CONN_SOCKS 1024

/* Every token is structured as follows:
 *   |     version     |  sock idx in the mempool |
 *   |31  (10 bits)  22|21       (22 bits)       0|
 * The version is used to handle multi-producer insertion in the mempool
 * freelist, every time a socket is put back in the mempool its version is
 * increased. This allows the cmpxchg instruction to fail if some updates have
 * been performed on the freelist in parallel with the current put, but the head
 * is the same as when the put began
 */
typedef __u32 token_t;
#define TOKEN_VER_BASE 0x00400000 /* Bit 22 */
#define TOKEN_IDX_MASK 0x003fffff /* Bits 0-21 */
#define TOKEN_VER_INC(t) ({ t += TOKEN_VER_BASE; })
#define TOKEN_GET_IDX(t) ({ t & TOKEN_IDX_MASK; })

/* TODO: study memory layout and alignment of this and other shared structures*/
struct conn_sock {
	token_t token;
	token_t freelist_next;
	struct conn_sock_id id;
	struct sock_queue qs[2];
	unsigned long waiting_recv[2];
	unsigned long waiting_send[2];
	char closing;
};

struct mempool {
	token_t freelist_head;
	struct conn_sock socks[H2OS_MAX_CONN_SOCKS];
};

static struct mempool *mp;

int conn_sock_init(struct h2os_shm_header *shmh)
{
	UK_ASSERT(shmh);

	mp = (void *)shmh + shmh->conn_sock_off;

	return 0;
}

unsigned conn_sock_get_idx(struct conn_sock *s)
{
	UK_ASSERT(s);

	return TOKEN_GET_IDX(s->token);
}

struct conn_sock *conn_sock_from_idx(unsigned idx)
{
	UK_ASSERT(idx < H2OS_MAX_CONN_SOCKS);

	return &mp->socks[idx];
}

struct conn_sock_id conn_sock_get_id(struct conn_sock *s)
{
	UK_ASSERT(s);

	return s->id;
}

int conn_sock_alloc(struct conn_sock **s, struct conn_sock_id *id)
{
	UK_ASSERT(s && id);

	token_t head, new_head;

	head = mp->freelist_head;
	do {
		if (TOKEN_GET_IDX(head) == H2OS_MAX_CONN_SOCKS)
			return -ENOMEM;
		*s = &mp->socks[TOKEN_GET_IDX(head)];
		new_head = (*s)->freelist_next;
	} while (!__atomic_compare_exchange_n(&mp->freelist_head, &head,
					      new_head, 0, __ATOMIC_SEQ_CST,
					      __ATOMIC_SEQ_CST));

	(*s)->id = *id;

	return 0;
}

void conn_sock_free(struct conn_sock *s)
{
	UK_ASSERT(s);

	token_t t = s->token;
	memset(s, 0, sizeof(*s));
	s->token = t;

	token_t head = mp->freelist_head;
	do
		s->freelist_next = head;
	while (!__atomic_compare_exchange_n(&mp->freelist_head, &head, s->token,
					    0, __ATOMIC_SEQ_CST,
					    __ATOMIC_SEQ_CST));
}

void conn_sock_close(struct conn_sock *s)
{
	UK_ASSERT(s);

	/* Flag the socket as closing, if it already was we need to free it */
	char expected = 0;
	if (!__atomic_compare_exchange_n(&s->closing, &expected, 1, 0,
					 __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
		conn_sock_free(s);
}

int conn_sock_send(struct conn_sock *s, struct h2os_shm_desc *desc,
		   enum conn_sock_dir dir, int nonblock)
{
	UK_ASSERT(s && desc);

	int was_empty;

	/* The loop handles spurious wakeups. TODO: can they happen? */
	while (sock_queue_produce(&s->qs[dir], desc, &was_empty)) {
		if (nonblock)
			return -EAGAIN;

		struct uk_thread *t = uk_thread_current();
		uk_preempt_disable();
		uk_thread_block(t);
		ukarch_store_n(&s->waiting_send[dir], t);

		if (!sock_queue_produce(&s->qs[dir], desc, &was_empty)) {
			ukarch_store_n(&s->waiting_send[dir], NULL);
			uk_thread_wake(t);
			uk_preempt_enable();
			break;
		}

		uk_preempt_enable();
		uk_sched_yield();

		ukarch_store_n(&s->waiting_send[dir], NULL);
	}

	if (was_empty) {
		unsigned long to_wake = ukarch_load_n(&s->waiting_recv[dir]);
		if (to_wake) {
			ukarch_store_n(&s->waiting_recv[dir], NULL);
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
	int sel = dir ^ 1;

	/* The loop handles spurious wakeups. TODO: can they happen? */
	while (sock_queue_consume(&s->qs[sel], desc, &was_full)) {
		if (nonblock)
			return -EAGAIN;

		struct uk_thread *t = uk_thread_current();
		uk_preempt_disable();
		uk_thread_block(t);
		ukarch_store_n(&s->waiting_recv[sel], t);

		if (!sock_queue_consume(&s->qs[sel], desc, &was_full)) {
			ukarch_store_n(&s->waiting_recv[sel], NULL);
			uk_thread_wake(t);
			uk_preempt_enable();
			break;
		}

		uk_preempt_enable();
		uk_sched_yield();

		ukarch_store_n(&s->waiting_recv[sel], NULL);
	}

	if (was_full) {
		unsigned long to_wake = ukarch_load_n(&s->waiting_send[sel]);
		if (to_wake) {
			ukarch_store_n(&s->waiting_recv[sel], 0);
			signal_send(dir == DIR_CLI_TO_SRV ? s->id.server_addr
				    : s->id.client_addr,
				    (struct signal *)&to_wake);
		}
	}

	return 0;
}