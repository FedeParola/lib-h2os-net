/*
 * Some sort of Copyright
 */

#include <errno.h>
#include <h2os/shm.h>
#include <uk/arch/limits.h>
#include <uk/init.h>
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

static int h2os_shm_init()
{
	int rc;
	struct qemu_ivshmem_info ivshmem_info;

	uk_pr_info("Initialize H2OS shared memory management...\n");

	rc = qemu_ivshmem_get_info(CONTROL_IVSHMEM_ID, &ivshmem_info);
	if (rc) {
		uk_pr_err("Error retrieving shared memory: %s\n",
			  strerror(-rc));
		return rc;
	}

	if (ivshmem_info.type != QEMU_IVSHMEM_TYPE_DOORBELL) {
		uk_pr_err("Unexpected QEMU ivshmem device type\n");
		return -EINVAL;
	}

	struct h2os_shm_header *shmh = ivshmem_info.addr;
	pool = ivshmem_info.addr + shmh->shm_buffers_off;

	rc = qemu_ivshmem_get_info(BUFFERS_IVSHMEM_ID, &ivshmem_info);
	if (rc) {
		uk_pr_err("Error retrieving shared memory: %s\n",
			  strerror(-rc));
		return rc;
	}

	if (ivshmem_info.type != QEMU_IVSHMEM_TYPE_PLAIN) {
		uk_pr_err("Unexpected QEMU ivshmem device type\n");
		return -EINVAL;
	}

	buffers = ivshmem_info.addr;

	return 0;
}
uk_lib_initcall(h2os_shm_init);

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