/*
 * Some sort of Copyright
 */

#ifndef __LIBUNIMSG_COMMON__
#define __LIBUNIMSG_COMMON__

#include <unimsg/shm.h>
#include <uk/alloc.h>
#include <uk/arch/paging.h>

#define UNIMSG_MAX_VMS 16
#define UNIMSG_BUFFERS_COUNT 2048
#define CONTROL_IVSHMEM_ID 0
#define BUFFERS_IVSHMEM_ID 1
#define SIDECAR_IVSHMEM_ID 2

#ifdef CONFIG_LIBUNIMSG_MEMORY_PROTECTION
void set_buffer_access(void *addr, int enabled);
#endif /* CONFIG_LIBUNIMSG_MEMORY_PROTECTION */

/**
 * Stores the offset of different components in the shared memory.
 */
struct unimsg_shm_header {
	unsigned long vms_info_off;
	unsigned long vms_info_sz;
	unsigned long gw_backlog_off;
	unsigned long signal_off;
	unsigned long signal_sz;
	unsigned long listen_sock_map_off;
	unsigned long listen_socks_off;
	unsigned long listen_sock_sz;
	unsigned long conn_pool_off;
	unsigned long conn_conns_off;
	unsigned long conn_sz;
	unsigned long conn_queue_sz;
	unsigned long shm_buffers_off;
};

extern struct uk_alloc *unimsg_allocator;

#endif /* __LIBUNIMSG_COMMON__ */