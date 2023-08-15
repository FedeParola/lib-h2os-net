/*
 * Some sort of Copyright
 */

#include <errno.h>
#include <unimsg/shm.h>
#include <uk/arch/limits.h>
#include <uk/plat/qemu/ivshmem.h>
#include <uk/print.h>
#include <string.h>
#include "common.h"
#include "ring.h"

struct buffer {
	char data[UNIMSG_SHM_BUFFER_SIZE];
};

static struct unimsg_ring *pool;
static struct buffer *buffers;

int shm_init(struct qemu_ivshmem_info control_ivshmem,
	     struct qemu_ivshmem_info buffers_ivshmem)
{
	struct unimsg_shm_header *shmh = control_ivshmem.addr;
	pool = control_ivshmem.addr + shmh->shm_buffers_off;

	buffers = buffers_ivshmem.addr;

	return 0;
}

int _unimsg_buffer_get(struct unimsg_shm_desc *desc)
{
	if (!desc)
		return -EINVAL;

	unsigned idx;
	if (unimsg_ring_dequeue(pool, &idx, 1))
		return -ENOMEM;
	desc->addr = &buffers[idx];
	desc->size = __PAGE_SIZE; /* Fixed size for now */

#ifdef CONFIG_LIBUNIMSG_MEMORY_PROTECTION
	/* TODO: what to do here? Can setting the access actually fail? */
	int __maybe_unused rc = enable_buffer_access(*desc);
	UK_ASSERT(!rc);
#endif

	return 0;
}

int _unimsg_buffer_put(struct unimsg_shm_desc *desc)
{
	if (!desc)
		return -EINVAL;

#ifdef CONFIG_LIBUNIMSG_MEMORY_PROTECTION
	/* TODO: what to do here? Can setting the access actually fail? */
	int __maybe_unused rc = disable_buffer_access(*desc);
	UK_ASSERT(!rc);
#endif

	memset(desc->addr, 0, UNIMSG_SHM_BUFFER_SIZE);

	/* TODO: check the validity of the addr of the buffer (i.e., page
	 * aligned, in the right range)
	 */
	unsigned idx = (desc->addr - (void *)buffers) / __PAGE_SIZE;
	unimsg_ring_enqueue(pool, &idx, 1);
	return 0;
}