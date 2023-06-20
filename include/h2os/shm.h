/*
 * Some sort of Copyright
 */

#ifndef __LIBH2OS_SHM__
#define __LIBH2OS_SHM__

#include <h2os/api.h>
#include <uk/arch/types.h>

struct h2os_shm_desc {
	void *addr;
	unsigned size;
};

H2OS_API_DEFINE(h2os_buffer_get, struct h2os_shm_desc *, desc);

H2OS_API_DEFINE(h2os_buffer_put, struct h2os_shm_desc *, desc);

#endif /* __LIBH2OS_SHM__ */