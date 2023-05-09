/*
 * Some sort of Copyright
 */

#ifndef __LIBH2OS_SHM__
#define __LIBH2OS_SHM__

struct h2os_shm_desc {
	unsigned long idx;
	/* Add size for variable size buffers */
};

int h2os_shm_get_buffer(struct h2os_shm_desc desc);
int h2os_shm_put_buffer(struct h2os_shm_desc *desc);

#endif /* __LIBH2OS_SHM__ */