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

void *h2os_buffer_get_addr(struct h2os_shm_desc desc)
{
	return &buffers[idxpool_get_idx(desc.token)];
}

int h2os_buffer_get(struct h2os_shm_desc *desc)
{
	return idxpool_get(pool, &desc->token);
}

void h2os_buffer_put(struct h2os_shm_desc desc)
{
	idxpool_put(pool, desc.token);
}