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
#include "idxpool.h"

struct buffer {
	char data[H2OS_SHM_BUFFER_SIZE];
};

static struct idxpool *pool;
static struct buffer *buffers;

int shm_init(struct qemu_ivshmem_info control_ivshmem,
	     struct qemu_ivshmem_info buffers_ivshmem)
{
	struct h2os_shm_header *shmh = control_ivshmem.addr;
	pool = control_ivshmem.addr + shmh->shm_buffers_off;

	buffers = buffers_ivshmem.addr;

	return 0;
}

void *buffer_get_addr(struct h2os_shm_desc desc)
{
	return &buffers[idxpool_get_idx(desc.token)];
}

int _h2os_buffer_get_addr(struct h2os_shm_desc *desc, void **addr)
{
	if (!desc || !addr)
		return -EINVAL;

	/* TODO: check array overflow */
	*addr = buffer_get_addr(*desc);

	return 0;
}

int _h2os_buffer_get(struct h2os_shm_desc *desc)
{
	if (!desc)
		return -EINVAL;

	if (idxpool_get(pool, &desc->token))
		return -ENOMEM;
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
	idxpool_put(pool, desc->token);
	return 0;
}