/*
 * Some sort of Copyright
 */

#include <errno.h>
#include <string.h>
#include <uk/arch/spinlock.h>
#include <uk/assert.h>
#include <uk/preempt.h>
#include <uk/sched.h>
#include <uk/thread.h>
#include "backlog_queue.h"
#include "conn_sock.h"
#include "jhash.h"
#include "listen_sock.h"

struct listen_sock_id {
	__u32 addr;
	__u16 port;
};

struct listen_sock {
	__u32 next;
	__u32 prev;
	__u32 freelist_next;
	__u32 bucket;
	unsigned refcount;
	struct listen_sock_id key;
	struct backlog_queue backlog;
	unsigned long waiting_accept;
};

struct bucket {
	__u32 head;
	struct __spinlock lock;
};

struct listen_sock_map {
	__u32 freelist_head;
	struct __spinlock freelist_lock;
	struct bucket buckets[H2OS_MAX_LISTEN_SOCKS];
	struct listen_sock socks[H2OS_MAX_LISTEN_SOCKS];
};

struct listen_sock_map *map;

int listen_sock_init(struct h2os_shm_header *shmh)
{
	UK_ASSERT(shmh);

	map = (void *)shmh + shmh->listen_sock_off;

	return 0;
}

int listen_sock_create(__u32 addr, __u16 port, struct listen_sock **s)
{
	UK_ASSERT(s);

	struct listen_sock_id key = {
		.addr = addr,
		.port = port,
	};

	struct bucket *bkt = &map->buckets[jhash(&key, sizeof(key), 0)
					   % H2OS_MAX_LISTEN_SOCKS];
	ukarch_spin_lock(&bkt->lock);

	struct listen_sock *curr = NULL;
	unsigned next = bkt->head;
	while (next != H2OS_MAX_LISTEN_SOCKS) {
		curr = &map->socks[next];
		if (!memcmp(&key, &curr->key, sizeof(key))) {
			ukarch_spin_unlock(&bkt->lock);
			return -EEXIST;
		}
		next = map->socks[next].next;
	}

	/* Allocate a new entry */
	ukarch_spin_lock(&map->freelist_lock);
	if (map->freelist_head == H2OS_MAX_LISTEN_SOCKS) {
		ukarch_spin_unlock(&map->freelist_lock);
		return -ENOMEM;
	}
	unsigned new_idx = map->freelist_head;
	map->freelist_head = map->socks[new_idx].freelist_next;
	ukarch_spin_unlock(&map->freelist_lock);

	*s = &map->socks[new_idx];
	(*s)->next = H2OS_MAX_LISTEN_SOCKS;
	(*s)->key = key;

	if (!curr) {
		/* The bucket was empy, add in head */
		bkt->head = new_idx;
		(*s)->prev = H2OS_MAX_LISTEN_SOCKS;
	} else {
		curr->next = new_idx;
		(*s)->prev = curr - map->socks;
	}

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

	struct bucket *bkt = &map->buckets[jhash(&key, sizeof(key), 0)
					   % H2OS_MAX_LISTEN_SOCKS];
	ukarch_spin_lock(&bkt->lock);

	struct listen_sock *curr = NULL;
	unsigned next = bkt->head;
	while (next != H2OS_MAX_LISTEN_SOCKS) {
		curr = &map->socks[next];
		if (!memcmp(&key, &curr->key, sizeof(key)))
			break;
		next = map->socks[next].next;
	}

	if (!curr || next == H2OS_MAX_LISTEN_SOCKS) {
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
	while (!backlog_queue_drain_one(&s->backlog, &cs_idx))
		conn_sock_close(conn_sock_from_idx(cs_idx));

	memset(s, 0, sizeof(*s));

	ukarch_spin_lock(&map->freelist_lock);
	s->freelist_next = map->freelist_head;
	/* Get the index of this sock */
	map->freelist_head = s - map->socks;
	ukarch_spin_unlock(&map->freelist_lock);
}

/**
 * Removes the socket from the map so that no new connect can reference it. If
 * there are some threads referencing the socket returning the object to the
 * freelist is postponed to the last release operation.
 */
void listen_sock_close(struct listen_sock *s)
{
	UK_ASSERT(s);

	struct bucket *bkt = &map->buckets[s->bucket];
	ukarch_spin_lock(&bkt->lock);
	if (s->prev == H2OS_MAX_LISTEN_SOCKS)
		bkt->head = s->next;
	else
		map->socks[s->prev].next = s->next;
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

int listen_sock_send_conn(struct listen_sock *s, struct conn_sock *cs)
{
	UK_ASSERT(s && cs);

	unsigned sock_idx = s - map->socks;
	int was_empty;
	if (backlog_queue_produce(&s->backlog, sock_idx, &was_empty))
		return -EAGAIN;

	if (was_empty) {
		unsigned long to_wake = ukarch_load_n(&s->waiting_accept);
		if (to_wake) {
			ukarch_store_n(&s->waiting_accept, NULL);
			signal_send(s->key.addr, (struct signal *)&to_wake);
		}
	}

	return 0;
}

int listen_sock_recv_conn(struct listen_sock *s, struct conn_sock **cs,
			  int nonblock)
{
	UK_ASSERT(s && cs);

	unsigned sock_idx;
	/* The loop handles spurious wakeups. TODO: can they happen? */
	while (backlog_queue_consume(&s->backlog, &sock_idx)) {
		if (nonblock)
			return -EAGAIN;

		struct uk_thread *t = uk_thread_current();
		uk_preempt_disable();
		uk_thread_block(t);
		ukarch_store_n(&s->waiting_accept, uk_thread_current());

		if (!backlog_queue_consume(&s->backlog, &sock_idx)) {
			ukarch_store_n(&s->waiting_accept, NULL);
			uk_thread_wake(t);
			uk_preempt_enable();
			break;
		}

		uk_preempt_enable();
		uk_sched_yield();

		ukarch_store_n(&s->waiting_accept, NULL);
	}
	
	*cs = conn_sock_from_idx(sock_idx);

	return 0;
}