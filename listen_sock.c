/*
 * Some sort of Copyright
 */

#include <errno.h>
#include <string.h>
#include <uk/arch/spinlock.h>
#include <uk/assert.h>
#include <uk/sched.h>
#include <uk/thread.h>
#include "connection.h"
#include "jhash.h"
#include "listen_sock.h"
#include "ring.h"
#include "signal.h"

struct listen_sock_id {
	__u32 addr;
	__u16 port;
};

struct listen_sock {
	unsigned next;
	unsigned prev;
	unsigned freelist_next;
	unsigned bucket;
	unsigned refcount;
	struct listen_sock_id key;
	unsigned long waiting_accept;
	struct unimsg_ring backlog;
};

struct bucket {
	unsigned head;
	struct __spinlock lock;
};

struct listen_sock_map {
	unsigned size;
	unsigned freelist_head;
	struct __spinlock freelist_lock;
	struct bucket buckets[];
};

static unsigned long sock_sz;
static struct listen_sock_map *map;
static struct listen_sock *socks;

int listen_sock_init(struct unimsg_shm_header *shmh)
{
	UK_ASSERT(shmh);

	map = (void *)shmh + shmh->listen_sock_map_off;
	socks = (void *)shmh + shmh->listen_socks_off;
	sock_sz = shmh->listen_sock_sz;

	return 0;
}

static unsigned get_idx(struct listen_sock *s)
{
	UK_ASSERT(s);

	return ((void *)s - (void *)socks) / sock_sz;
}

static struct listen_sock *get_sock(unsigned idx)
{
	return (void *)socks + sock_sz * idx;
}

int listen_sock_create(__u32 addr, __u16 port, struct listen_sock **s)
{
	UK_ASSERT(s);

	struct listen_sock_id key = {
		.addr = addr,
		.port = port,
	};

	unsigned bkt_idx = jhash(&key, sizeof(key), 0) % map->size;
	struct bucket *bkt = &map->buckets[bkt_idx];
	ukarch_spin_lock(&bkt->lock);

	struct listen_sock *curr = NULL;
	unsigned next = bkt->head;
	while (next != map->size) {
		curr = get_sock(next);
		if (!memcmp(&key, &curr->key, sizeof(key))) {
			ukarch_spin_unlock(&bkt->lock);
			return -EEXIST;
		}
		next = curr->next;
	}

	/* Allocate a new entry */
	ukarch_spin_lock(&map->freelist_lock);
	if (map->freelist_head == map->size) {
		ukarch_spin_unlock(&map->freelist_lock);
		return -ENOMEM;
	}
	unsigned new_idx = map->freelist_head;
	*s = get_sock(new_idx);
	map->freelist_head = (*s)->freelist_next;
	ukarch_spin_unlock(&map->freelist_lock);

	(*s)->key = key;
	(*s)->next = bkt->head;
	(*s)->prev = map->size;
	(*s)->bucket = bkt_idx;
	(*s)->refcount = 1;
	bkt->head = new_idx;

	ukarch_spin_unlock(&bkt->lock);

	return 0;
}

int listen_sock_lookup_acquire(__u32 addr, __u16 port, struct listen_sock **s)
{
	UK_ASSERT(s);

	struct listen_sock_id key = {
		.addr = addr,
		.port = port,
	};

	struct bucket *bkt =
			&map->buckets[jhash(&key, sizeof(key), 0) % map->size];
	ukarch_spin_lock(&bkt->lock);

	struct listen_sock *curr = NULL;
	unsigned next = bkt->head;
	while (next != map->size) {
		curr = get_sock(next);
		if (!memcmp(&key, &curr->key, sizeof(key)))
			break;
		next = curr->next;
	}

	if (!curr || next == map->size) {
		ukarch_spin_unlock(&bkt->lock);
		return -ENOENT;
	}

	curr->refcount++;
	ukarch_spin_unlock(&bkt->lock);
	*s = curr;

	return 0;
}

static void listen_sock_free(struct listen_sock *s)
{
	UK_ASSERT(s);

	/* Perform the socket cleanup, close all the pending connections
	 * in the backlog and free the socket
	 */
	unsigned cs_idx;
	while (!unimsg_ring_dequeue(&s->backlog, &cs_idx, 1))
		conn_close(conn_from_idx(cs_idx), CONN_SIDE_SRV);

	s->next = map->size;
	s->prev = map->size;
	s->bucket = map->size;
	s->key = (struct listen_sock_id){0};
	s->waiting_accept = 0;
	unimsg_ring_reset(&s->backlog);

	ukarch_spin_lock(&map->freelist_lock);
	s->freelist_next = map->freelist_head;
	map->freelist_head = get_idx(s);
	ukarch_spin_unlock(&map->freelist_lock);
}

void listen_sock_close(struct listen_sock *s)
{
	UK_ASSERT(s);

	struct bucket *bkt = &map->buckets[s->bucket];
	ukarch_spin_lock(&bkt->lock);
	if (s->prev == map->size)
		bkt->head = s->next;
	else
		get_sock(s->prev)->next = s->next;
	s->refcount--;
	ukarch_spin_unlock(&bkt->lock);

	if (s->refcount == 0)
		listen_sock_free(s);
}

void listen_sock_release(struct listen_sock *s)
{
	UK_ASSERT(s);

	/* We still use the bucket's lock even if the socket might no longer be
	 * in the bucket
	 */
	struct bucket *bkt = &map->buckets[s->bucket];
	ukarch_spin_lock(&bkt->lock);
	s->refcount--;
	ukarch_spin_unlock(&bkt->lock);

	if (s->refcount == 0)
		listen_sock_free(s);	
}

int listen_sock_send_conn(struct listen_sock *s, struct conn *c)
{
	UK_ASSERT(s && c);

	unsigned conn_idx = conn_get_idx(c);
	if (unimsg_ring_enqueue(&s->backlog, &conn_idx, 1))
		return -EAGAIN;

	unsigned long to_wake = __atomic_load_n(&s->waiting_accept,
						__ATOMIC_ACQUIRE);
	if (to_wake &&
	    __atomic_compare_exchange_n(&s->waiting_accept, &to_wake, NULL, 0,
					__ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
		signal_send(s->key.addr, (struct signal *)&to_wake);

	return 0;
}

int listen_sock_recv_conn(struct listen_sock *s, struct conn **c, int nonblock)
{
	UK_ASSERT(s && c);

	unsigned conn_idx;
	/* The loop handles spurious wakeups. TODO: can they happen? */
	while (unimsg_ring_dequeue(&s->backlog, &conn_idx, 1)) {
		if (nonblock)
			return -EAGAIN;

		struct uk_thread *t = uk_thread_current();
		uk_thread_block(t);
		__atomic_store_n(&s->waiting_accept, t, __ATOMIC_RELEASE);

		if (!unimsg_ring_dequeue(&s->backlog, &conn_idx, 1)) {
			__atomic_store_n(&s->waiting_accept, NULL,
					 __ATOMIC_RELEASE);
			uk_thread_wake(t);
			break;
		}

		uk_sched_yield();
	}
	
	*c = conn_from_idx(conn_idx);

	return 0;
}

int listen_sock_poll_check(struct listen_sock *s)
{
	UK_ASSERT(s);

	return unimsg_ring_count(&s->backlog) > 0;
}

int listen_sock_poll_set(struct listen_sock *s)
{
	UK_ASSERT(s);

	struct uk_thread *t = uk_thread_current();
	__atomic_store_n(&s->waiting_accept, t, __ATOMIC_SEQ_CST);

	return unimsg_ring_count(&s->backlog) > 0;
}

int listen_sock_poll_clean(struct listen_sock *s)
{
	UK_ASSERT(s);

	__atomic_store_n(&s->waiting_accept, NULL, __ATOMIC_SEQ_CST);

	return unimsg_ring_count(&s->backlog) > 0;
}