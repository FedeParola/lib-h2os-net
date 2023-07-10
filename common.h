/*
 * Some sort of Copyright
 */

#ifndef __LIBUNIMSG_COMMON__
#define __LIBUNIMSG_COMMON__

#include <uk/alloc.h>
#include <uk/arch/paging.h>

#define UNIMSG_MAX_VMS 16
#define UNIMSG_SHM_BUFFER_SIZE PAGE_SIZE
#define UNIMSG_SHM_BUFFERS_COUNT 64
#define CONTROL_IVSHMEM_ID 0
#define BUFFERS_IVSHMEM_ID 1

#ifdef CONFIG_LIBUNIMSG_MEMORY_PROTECTION
#include <unimsg/shm.h>

int enable_buffer_access(struct unimsg_shm_desc desc);
int disable_buffer_access(struct unimsg_shm_desc desc);
#endif /* CONFIG_LIBUNIMSG_MEMORY_PROTECTION */

/**
 * Stores the offset of different components in the shared memory.
 */
struct unimsg_shm_header {
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