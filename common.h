/*
 * Some sort of Copyright
 */

#ifndef __LIBH2OS_COMMON__
#define __LIBH2OS_COMMON__

#include <uk/alloc.h>
#include <uk/arch/paging.h>

#define H2OS_MAX_VMS 16
#define H2OS_SHM_BUFFER_SIZE PAGE_SIZE
#define H2OS_SHM_BUFFERS_COUNT 64
#define CONTROL_IVSHMEM_ID 0
#define BUFFERS_IVSHMEM_ID 1

#ifdef CONFIG_LIBH2OS_MEMORY_PROTECTION
#include <h2os/shm.h>

int enable_buffer_access(struct h2os_shm_desc desc);
int disable_buffer_access(struct h2os_shm_desc desc);
void *buffer_get_addr(struct h2os_shm_desc desc); /* Defined in shm.c */
#endif /* CONFIG_LIBH2OS_MEMORY_PROTECTION */

/**
 * Stores the offset of different components in the shared memory.
 */
struct h2os_shm_header {
	unsigned long signal_off;
	unsigned long listen_sock_off;
	unsigned long conn_sock_off;
	unsigned long shm_buffers_off;
};

extern struct uk_alloc *h2os_allocator;

#endif /* __LIBH2OS_COMMON__ */