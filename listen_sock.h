/*
 * Some sort of Copyright
 */

#ifndef __LIBH2OS_LISTENING_SOCK__
#define __LIBH2OS_LISTENING_SOCK__

#include "common.h"

struct listen_sock;

/**
 * Setup access to the listening socks map in shared memory
 * @param shmh A pointer to the shared memory header
 * @return 0 on success, an error code on error
*/
int listen_sock_init(struct h2os_shm_header *shmh);

int listen_sock_create(__u32 addr, __u16 port, struct listen_sock **s);

int listen_sock_lookup_acquire(__u32 addr, __u16 port, struct listen_sock **s);

void listen_sock_release(struct listen_sock *s);

int listen_sock_send_conn(struct listen_sock *s, struct conn_sock *cs);

int listen_sock_recv_conn(struct listen_sock *s, struct conn_sock **cs,
			  int nonblock);

#endif /* __LIBH2OS_LISTENING_SOCK__ */