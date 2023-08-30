/*
 * Some sort of Copyright
 */

#ifndef __LIBUNIMSG_CONNECTION__
#define __LIBUNIMSG_CONNECTION__

#include <unimsg/shm.h>
#include "common.h"

enum conn_dir {
	DIR_CLI_TO_SRV = 0,
	DIR_SRV_TO_CLI = 1,
};

struct conn_id {
	unsigned client_id;
	__u32 client_addr;
	__u16 client_port;
	unsigned server_id;
	__u32 server_addr;
	__u16 server_port;
};

struct conn;

int conn_init(struct unimsg_shm_header *shmh);

unsigned conn_get_idx(struct conn *c);

struct conn *conn_from_idx(unsigned idx);

struct conn_id conn_get_id(struct conn *c);

int conn_alloc(struct conn **c, struct conn_id *id);

void conn_free(struct conn *c);

void conn_close(struct conn *c, enum conn_dir dir);

int conn_send(struct conn *c, struct unimsg_shm_desc *descs, unsigned ndescs,
	      enum conn_dir dir, int nonblock);

int conn_recv(struct conn *c, struct unimsg_shm_desc *descs, unsigned *ndescs,
	      enum conn_dir dir, int nonblock);

#endif /* __LIBUNIMSG_CONNECTION__ */