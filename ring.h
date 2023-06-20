/*
 * Some sort of Copyright
 */

#ifndef __LIBH2OS_RING__
#define __LIBH2OS_RING__

#include <errno.h>
#include <string.h>
#include <uk/arch/lcpu.h>
#include <uk/essentials.h>

#define __always_inline inline __attribute__((always_inline))
#define __cache_aligned __align(CACHE_LINE_SIZE)

#define H2OS_RING_F_SP 0x1
#define H2OS_RING_F_SC 0x2

#define MASK (r->size - 1)

struct h2os_ring_headtail {
	volatile __u32 head;
	volatile __u32 tail;
};

struct h2os_ring {
	unsigned size;
	unsigned esize;
	int flags;
	char pad0 __cache_aligned;
	struct h2os_ring_headtail prod __cache_aligned;
	char pad1 __cache_aligned;
	struct h2os_ring_headtail cons __cache_aligned;
	char pad2 __cache_aligned;
	char objs[] __cache_aligned;
};

static __always_inline int
h2os_ring_enqueue_sp(struct h2os_ring *r, const void *objs, unsigned n)
{
	__u32 cons = __atomic_load_n(&r->cons.tail, __ATOMIC_ACQUIRE);
	if (r->prod.tail - cons + n > r->size)
		return -EAGAIN;

	char *firstobj = r->objs + (r->prod.tail & MASK) * r->esize;
	memcpy(firstobj, objs, n * r->esize);

	__atomic_store_n(&r->prod.tail, r->prod.tail + n, __ATOMIC_RELEASE);

	return 0;
}

static __always_inline int
h2os_ring_enqueue_mp(struct h2os_ring *r, const void *objs, unsigned n)
{
	__u32 old_head, cons;

	old_head = __atomic_load_n(&r->prod.head, __ATOMIC_RELAXED);
	do {
		cons = __atomic_load_n(&r->cons.tail, __ATOMIC_ACQUIRE);
		if (old_head - cons + n > r->size)
			return -EAGAIN;
	} while (!__atomic_compare_exchange_n(&r->prod.head, &old_head,
					      old_head + n, 0, __ATOMIC_SEQ_CST,
					      __ATOMIC_SEQ_CST));

	char *firstobj = r->objs + (old_head & MASK) * r->esize;
	memcpy(firstobj, objs, n * r->esize);

	while (__atomic_load_n(&r->prod.tail, __ATOMIC_RELAXED) != old_head)
		__builtin_ia32_pause();

	__atomic_store_n(&r->prod.tail, r->prod.tail + n, __ATOMIC_RELEASE);

	return 0;
}

static __always_inline int
h2os_ring_enqueue(struct h2os_ring *r, const void *objs, unsigned n)
{
	if (r->flags & H2OS_RING_F_SP)
		return h2os_ring_enqueue_sp(r, objs, n);
	else
		return h2os_ring_enqueue_mp(r, objs, n);
}

static __always_inline int
h2os_ring_dequeue_sc(struct h2os_ring *r, void *objs, unsigned n)
{
	__u32 prod = __atomic_load_n(&r->prod.tail, __ATOMIC_ACQUIRE);
	if (prod - r->cons.tail < n)
		return -EAGAIN;

	char *firstobj = r->objs + (r->cons.tail & MASK) * r->esize;
	memcpy(objs, firstobj, n * r->esize);

	__atomic_store_n(&r->cons.tail, r->cons.tail + 1, __ATOMIC_RELEASE);

	return 0;
}

static __always_inline int
h2os_ring_dequeue_mc(struct h2os_ring *r, void *objs, unsigned n)
{
	__u32 old_head, prod;

	old_head = __atomic_load_n(&r->cons.head, __ATOMIC_RELAXED);
	do {
		prod = __atomic_load_n(&r->prod.tail, __ATOMIC_ACQUIRE);
		if (prod - old_head < n)
			return -EAGAIN;
	} while (!__atomic_compare_exchange_n(&r->cons.head, &old_head,
					      old_head + n, 0, __ATOMIC_SEQ_CST,
					      __ATOMIC_SEQ_CST));

	char *firstobj = r->objs + (old_head & MASK) * r->esize;
	memcpy(firstobj, objs, n * r->esize);

	while (__atomic_load_n(&r->cons.tail, __ATOMIC_RELAXED) != old_head)
		__builtin_ia32_pause();

	__atomic_store_n(&r->cons.tail, r->cons.tail + n, __ATOMIC_RELEASE);

	return 0;
}

static __always_inline int
h2os_ring_dequeue(struct h2os_ring *r, void *objs, unsigned n)
{
	if (r->flags & H2OS_RING_F_SC)
		return h2os_ring_dequeue_sc(r, objs, n);
	else
		return h2os_ring_dequeue_mc(r, objs, n);
}

static inline size_t h2os_ring_objs_memsize(const struct h2os_ring *r)
{
	return r->esize * r->size;
}

static inline size_t h2os_ring_memsize(const struct h2os_ring *r)
{
	return sizeof(*r) + r->esize * r->size;
}

#undef MASK

#endif /* __LIBH2OS_RING__ */
