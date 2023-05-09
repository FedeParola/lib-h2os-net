/*
 * Some sort of Copyright
 */

#ifndef __LIBH2OS_COMMON__
#define __LIBH2OS_COMMON__

#include "backlog_queue.h"
#include "signal.h"

#define H2OS_MAX_VMS 16
#define H2OS_MAX_LISTEN_SOCKS 1024
#define H2OS_SHM_BUFFER_SIZE 64
#define H2OS_SHM_BUFFERS_COUNT 64
#define IVSHMEM_DEVICE_ID 0

/* Stores the offset of different components in the shared memory */
struct h2os_shm_header {
	unsigned long signal_off;
	unsigned long listen_sock_off;
	unsigned long conn_sock_off;
};

#endif /* __LIBH2OS_COMMON__ */