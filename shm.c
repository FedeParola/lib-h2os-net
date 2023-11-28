/*
 * Some sort of Copyright
 */

#include <errno.h>
#include <unimsg/shm.h>
#include <uk/arch/limits.h>
#include <ivshmem.h>
#include <uk/print.h>
#include <string.h>
#include "common.h"
#include "ring.h"

struct buffer {
	char data[UNIMSG_BUFFER_SIZE];
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

void *unimsg_buffer_get_addr(struct unimsg_shm_desc *desc)
{
	return desc->idx * UNIMSG_BUFFER_SIZE + (void *)buffers + desc->off;
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
		set_buffer_access(addr, 1);
#endif
		descs[i].size = UNIMSG_BUFFER_SIZE - UNIMSG_BUFFER_HEADROOM;
		descs[i].off = UNIMSG_BUFFER_HEADROOM;
		descs[i].idx = idx[i];
		descs[i].addr = unimsg_buffer_get_addr(&descs[i]);
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
		idx[i] = descs[i].idx;
		void *addr = (void *)buffers + idx[i] * UNIMSG_BUFFER_SIZE;
#ifdef CONFIG_LIBUNIMSG_MEMORY_PROTECTION
		set_buffer_access(addr, 0);
#endif
		memset(addr, 0, UNIMSG_BUFFER_SIZE);
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

int unimsg_buffer_put_internal(struct unimsg_shm_desc *descs, unsigned ndescs)
{
	UK_ASSERT(descs && ndescs <= UNIMSG_MAX_DESCS_BULK && ndescs > 0);

	unsigned idx[UNIMSG_MAX_DESCS_BULK];
	for (unsigned i = 0; i < ndescs; i++) {
		idx[i] = descs[i].idx;
		void *addr = (void *)buffers + idx[i] * UNIMSG_BUFFER_SIZE;
		memset(addr, 0, UNIMSG_BUFFER_SIZE);
	}

	unimsg_ring_enqueue(pool, idx, ndescs);

	return 0;
}