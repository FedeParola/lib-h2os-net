/*
 * Some sort of Copyright
 */

#include <errno.h>
#include <uk/init.h>
#include <uk/plat/qemu/ivshmem.h>
#include <uk/print.h>
#include <string.h>
#include "common.h"

static int h2os_shm_init()
{
	int rc;
	struct qemu_ivshmem_info ivshmem_info;

	uk_pr_info("Initialize H2OS shared memory management...\n");

	rc = qemu_ivshmem_get_info(IVSHMEM_DEVICE_ID, &ivshmem_info);
	if (rc) {
		uk_pr_err("Error retrieving shared memory: %s\n",
			  strerror(-rc));
		return rc;
	}

	if (ivshmem_info.type != QEMU_IVSHMEM_TYPE_DOORBELL) {
		uk_pr_err("Unexpected QEMU ivshmem device type\n");
		return -EINVAL;
	}

	return 0;
}
uk_lib_initcall(h2os_shm_init);