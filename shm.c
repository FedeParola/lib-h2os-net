/*
 * Some sort of Copyright
 */

#include <errno.h>
#include <h2os/shm.h>
#include <uk/arch/limits.h>
#include <uk/plat/qemu/ivshmem.h>
#include <uk/print.h>
#include <string.h>
#include "common.h"
#include "ring.h"

struct buffer {
	char data[H2OS_SHM_BUFFER_SIZE];
};

static struct h2os_ring *pool;
static struct buffer *buffers;

int shm_init(struct qemu_ivshmem_info control_ivshmem,
	     struct qemu_ivshmem_info buffers_ivshmem)
{
	struct h2os_shm_header *shmh = control_ivshmem.addr;
	pool = control_ivshmem.addr + shmh->shm_buffers_off;

	buffers = buffers_ivshmem.addr;

	return 0;
}

int _h2os_buffer_get(struct h2os_shm_desc *desc)
{
	if (!desc)
		return -EINVAL;

	unsigned idx;
	if (h2os_ring_dequeue(pool, &idx, 1))
		return -ENOMEM;
	desc->addr = &buffers[idx];
	desc->size = __PAGE_SIZE; /* Fixed size for now */

#ifdef CONFIG_LIBH2OS_MEMORY_PROTECTION
	/* TODO: what to do here? Can setting the access actually fail? */
	UK_ASSERT(!enable_buffer_access(*desc));
#endif

	return 0;
}

int _h2os_buffer_put(struct h2os_shm_desc *desc)
{
	if (!desc)
		return -EINVAL;

#ifdef CONFIG_LIBH2OS_MEMORY_PROTECTION
	/* TODO: what to do here? Can setting the access actually fail? */
	UK_ASSERT(!disable_buffer_access(*desc));
#endif
	/* TODO: check the validity of the addr of the buffer (i.e., page
	 * aligned, in the right range)
	 */
	unsigned idx = (desc->addr - (void *)buffers) / __PAGE_SIZE;
	h2os_ring_enqueue(pool, &idx, 1);
	return 0;
}