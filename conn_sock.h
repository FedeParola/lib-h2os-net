/*
 * Some sort of Copyright
 */

#ifndef __LIBUNIMSG_CONN_SOCK__
#define __LIBUNIMSG_CONN_SOCK__

#include <unimsg/shm.h>
#include "common.h"

enum conn_sock_dir {
	DIR_CLI_TO_SRV = 0,
	DIR_SRV_TO_CLI = 1,
};

struct conn_sock_id {
	__u32 client_addr;
	__u16 client_port;
	__u32 server_addr;
	__u16 server_port;
};

struct conn_sock;

int conn_sock_init(struct unimsg_shm_header *shmh);

unsigned conn_sock_get_idx(struct conn_sock *s);

struct conn_sock *conn_sock_from_idx(unsigned idx);

struct conn_sock_id conn_sock_get_id(struct conn_sock *s);

int conn_sock_alloc(struct conn_sock **s, struct conn_sock_id *id);

void conn_sock_free(struct conn_sock *s);

void conn_sock_close(struct conn_sock *s, enum conn_sock_dir dir);

int conn_sock_send(struct conn_sock *s, struct unimsg_shm_desc *desc,
		   enum conn_sock_dir dir, int nonblock);

int conn_sock_recv(struct conn_sock *s, struct unimsg_shm_desc *desc,
		   enum conn_sock_dir dir, int nonblock);

#endif /* __LIBUNIMSG_CONN_SOCK__ */