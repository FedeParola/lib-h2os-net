/*
 * Some sort of Copyright
 */

#ifndef __LIBUNIMSG_LISTENING_SOCK__
#define __LIBUNIMSG_LISTENING_SOCK__

#include "common.h"

struct listen_sock;

/**
 * Sets up access to the listening socks map in shared memory.
 * @param shmh Pointer to the shared memory header
 * @return 0 on success, a negative errno value otherwise
*/
int listen_sock_init(struct unimsg_shm_header *shmh);

int listen_sock_create(__u32 addr, __u16 port, struct listen_sock **s);

int listen_sock_lookup_acquire(__u32 addr, __u16 port, struct listen_sock **s);

/**
 * Removes the socket from the map so that no new connect can reference it. If
 * there are some threads referencing the socket, returning the object to the
 * freelist is postponed to the last release operation.
 * @param s Listening socket to close
 */
void listen_sock_close(struct listen_sock *s);

void listen_sock_release(struct listen_sock *s);

int listen_sock_send_conn(struct listen_sock *s, struct conn *c);

int listen_sock_recv_conn(struct listen_sock *s, struct conn **c, int nonblock);

#endif /* __LIBUNIMSG_LISTENING_SOCK__ */