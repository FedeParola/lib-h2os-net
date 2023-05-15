/*
 * Some sort of Copyright
 */

#ifndef __LIBH2OS_COMMON__
#define __LIBH2OS_COMMON__

#include <uk/alloc.h>

#define H2OS_MAX_VMS 16
#define H2OS_SHM_BUFFER_SIZE __PAGE_SIZE
#define H2OS_SHM_BUFFERS_COUNT 64
#define CONTROL_IVSHMEM_ID 0
#define BUFFERS_IVSHMEM_ID 1
#ifdef CONFIG_LIBH2OS_MEMORY_PROTECTION
#define MPK_ENABLE_ACCESS()  ({ __builtin_ia32_wrpkru(0x0); })
#define MPK_DISABLE_ACCESS() ({ __builtin_ia32_wrpkru(0xffffffff); })
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