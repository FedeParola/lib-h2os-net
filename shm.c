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

void *h2os_buffer_get_addr(struct h2os_shm_desc desc)
{
	h2os_enter();
	void *ret = buffer_get_addr(desc);
	h2os_exit();
	return ret;
}

int h2os_buffer_get(struct h2os_shm_desc *desc)
{
	h2os_enter();
	int rc = 0;

	rc = idxpool_get(pool, &desc->token);
	if (rc)
		goto out;
	desc->size = __PAGE_SIZE; /* Fixed size for now */

#ifdef CONFIG_LIBH2OS_MEMORY_PROTECTION
	/* TODO: what to do here? Can setting the access actually fail? */
	UK_ASSERT(!enable_buffer_access(*desc));
#endif

out:
	h2os_exit();
	return rc;
}

void h2os_buffer_put(struct h2os_shm_desc desc)
{
	h2os_enter();

#ifdef CONFIG_LIBH2OS_MEMORY_PROTECTION
	/* TODO: what to do here? Can setting the access actually fail? */
	UK_ASSERT(!disable_buffer_access(desc));
#endif

	idxpool_put(pool, desc.token);

	h2os_exit();
}