/*
 * Some sort of Copyright
 */

#ifndef __LIBH2OS_IDXPOOL__
#define __LIBH2OS_IDXPOOL__

#include <uk/assert.h>

/* Every token is structured as follows:
 *   |     version     |  sock idx in the mempool |
 *   |31  (10 bits)  22|21       (22 bits)       0|
 * The version is used to handle multi-producer insertion in the mempool
 * freelist, every time a socket is put back in the mempool its version is
 * increased. This allows the cmpxchg instruction to fail if some updates have
 * been performed on the freelist in parallel with the current put, but the head
 * is the same as when the put began
 */
typedef __u32 idxpool_token_t;
#define TOKEN_VER_BASE 0x00400000 /* Bit 22 */
#define TOKEN_IDX_MASK 0x003fffff /* Bits 0-21 */
#define TOKEN_VER_INC(t) ({ t += TOKEN_VER_BASE; })

struct idxpool {
        unsigned size;
        idxpool_token_t head;
        idxpool_token_t nodes[];
};

static inline
unsigned idxpool_get_idx(idxpool_token_t t)
{
        return t & TOKEN_IDX_MASK;
}

static inline
int idxpool_get(struct idxpool *p, idxpool_token_t *t)
{
        UK_ASSERT(p && t);

        idxpool_token_t head = p->head, new_head;
        do {
		if (idxpool_get_idx(head) == p->size)
			return -ENOMEM;
		*t = head;
		new_head = p->nodes[idxpool_get_idx(head)];
	} while (!__atomic_compare_exchange_n(&p->head, &head, new_head, 0,
                                              __ATOMIC_SEQ_CST,
                                              __ATOMIC_SEQ_CST));

        return 0;
}

static inline
void idxpool_put(struct idxpool *p, idxpool_token_t t)
{
        UK_ASSERT(p && idxpool_get_idx(t) < p->size);

        idxpool_token_t head = p->head;
        TOKEN_VER_INC(t);
	do
		p->nodes[idxpool_get_idx(t)] = head;
	while (!__atomic_compare_exchange_n(&p->head, &head, t, 0,
                                            __ATOMIC_SEQ_CST,
                                            __ATOMIC_SEQ_CST));
}

#undef TOKEN_VER_BASE
#undef TOKEN_IDX_MASK
#undef TOKEN_VER_INC

#endif /* __LIBH2OS_IDXPOOL__ */