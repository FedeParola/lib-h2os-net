/*
 * Some sort of Copyright
 */

#ifndef __LIBH2OS_SHM__
#define __LIBH2OS_SHM__

#include <uk/arch/types.h>

struct h2os_shm_desc {
	__u32 token;
	unsigned size;
};

void *h2os_buffer_get_addr(struct h2os_shm_desc desc);
int h2os_buffer_get(struct h2os_shm_desc *desc);
void h2os_buffer_put(struct h2os_shm_desc desc);

#endif /* __LIBH2OS_SHM__ */