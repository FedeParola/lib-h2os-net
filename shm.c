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

int _unimsg_buffer_get(struct unimsg_shm_desc *descs, unsigned ndescs)
{
	if (!descs || ndescs > UNIMSG_MAX_DESCS_BULK)
		return -EINVAL;
	if (ndescs == 0)
		return 0;

	unsigned idx[UNIMSG_MAX_DESCS_BULK];
	if (unimsg_ring_dequeue(pool, idx, ndescs))
		return -ENOMEM;

	for (unsigned i = 0; i < ndescs; i++) {
		void *addr = &buffers[idx[i]];
#ifdef CONFIG_LIBUNIMSG_MEMORY_PROTECTION
		enable_buffer_access(addr);
#endif
		descs[i].addr = addr;
		descs[i].size = UNIMSG_SHM_BUFFER_SIZE;
	}

	return 0;
}

int _unimsg_buffer_put(struct unimsg_shm_desc *descs, unsigned ndescs)
{
	if (!descs || ndescs > UNIMSG_MAX_DESCS_BULK)
		return -EINVAL;
	if (ndescs == 0)
		return 0;

	unsigned idx[UNIMSG_MAX_DESCS_BULK];
	for (unsigned i = 0; i < ndescs; i++) {
		void *addr = descs[i].addr;
#ifdef CONFIG_LIBUNIMSG_MEMORY_PROTECTION
		disable_buffer_access(addr);
#endif
		memset(addr, 0, UNIMSG_SHM_BUFFER_SIZE);
		idx[i] = (addr - (void *)buffers) / UNIMSG_SHM_BUFFER_SIZE;
	}

	if (unimsg_ring_enqueue(pool, idx, ndescs)) {
		/* This can happen if the application is freeing buffers it
		 * doesn't own and it always represents a programming error that
		 * should be fixed. When memory protection is enabled this
		 * should already cause a crash when disabling buffer access
		 */
		UK_CRASH("Detected freeing of unknown shm buffer\n");
	}

	return 0;
}