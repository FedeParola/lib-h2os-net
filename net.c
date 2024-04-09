/*
 * Some sort of Copyright
 */

#include <qemu_ivshmem.h>
#include <string.h>
#include <unimsg/net.h>
#include <uk/mutex.h>
#include <uk/print.h>
#include <uk/refcount.h>
#include <uk/spinlock.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "connection.h"
#include "listen_sock.h"
#include "fmap.h"
#include "jhash.h"
#include "ring.h"
#include "sidecar.h"

#define MAX_SOCKETS 1024
#define PORTS_MAP_BUCKETS 64
#define SOCKETS_MAP_BUCKETS 64
#define EPHEMERAL_PORTS_FIRST 1024
#define EPHEMERAL_PORTS_COUNT (0xffff - EPHEMERAL_PORTS_FIRST + 1)

struct socket_id {
	__u32 raddr;
	__u16 rport;
	__u16 lport; /* 0 if socket not bound */
};

struct unimsg_sock {
	__atomic refcnt;
	struct uk_hlist_node list;
	struct socket_id id;
	struct listen_sock *ls;
	struct conn *conn;
	enum conn_side side;
};

struct vm_info {
	uint32_t addr;
	unsigned rt_bkt_next;
};

static unsigned long bitmap[UK_BMAP_SZ(MAX_SOCKETS)];
static void *sockets_ptrs[MAX_SOCKETS];
static struct uk_fmap sockets_fds;

static unsigned local_id;
static __u32 local_addr;

/* A local port can only be shared by a listening socket and the connections
 * accepted from it.
 */
struct port_info {
	struct uk_hlist_node list;
	__u16 port;
	unsigned users;
};
struct ports_bucket {
	struct uk_hlist_head ports;
	uk_spinlock lock;
};
static struct ports_bucket ports_map[PORTS_MAP_BUCKETS];
static __u16 ports_counter = 0;

static struct ports_bucket *port_get_bucket(__u16 port)
{
	return &ports_map[jhash(&port, sizeof(port), 0) % PORTS_MAP_BUCKETS];
}

static int port_acquire(__u16 port, int exclusive)
{
	int rc = 0;
	struct port_info *pinfo;

	struct ports_bucket *bucket = port_get_bucket(port);
	uk_spin_lock(&bucket->lock);
	uk_hlist_for_each_entry(pinfo, &bucket->ports, list) {
		if (pinfo->port == port)
			break;
	}
	if (pinfo) {
		if (exclusive)
			rc = -EADDRINUSE;
		else
			pinfo->users++;
	} else {
		pinfo = uk_malloc(unimsg_allocator, sizeof(*pinfo));
		if (!pinfo) {
			rc = -ENOMEM;
		} else {
			pinfo->port = port;
			pinfo->users = 1;
			uk_hlist_add_head(&pinfo->list, &bucket->ports);
		}
	}

	uk_spin_unlock(&bucket->lock);

	return rc;
}

static int port_acquire_new()
{
	__u16 port;
	int found = 0;

	for (int i = EPHEMERAL_PORTS_COUNT; i > 0; i--) {
		port = __atomic_fetch_add(&ports_counter, 1, __ATOMIC_SEQ_CST);
		port = port % EPHEMERAL_PORTS_COUNT + EPHEMERAL_PORTS_FIRST;

		if (!port_acquire(port, 1)) {
			found = 1;
			break;
		}
	}

	return found ? port : -1;
}

static void port_release(__u16 port)
{
	struct port_info *pinfo;

	struct ports_bucket *bucket = port_get_bucket(port);
	uk_spin_lock(&bucket->lock);
	uk_hlist_for_each_entry(pinfo, &bucket->ports, list) {
		if (pinfo->port == port)
			break;
	}

	UK_ASSERT(pinfo);

	if (pinfo->users-- == 0) {
		uk_hlist_del(&pinfo->list);
		uk_free(unimsg_allocator, pinfo);
	}
	uk_spin_unlock(&bucket->lock);
}

static struct unimsg_ring *gw_backlog;
static unsigned long vms_info_sz;
static struct vm_info *vm_info;
static unsigned *rt_buckets;

/* Helpers to handle FDs */
static inline struct unimsg_sock *sock_acquire(int fd)
{
	struct unimsg_sock *s = uk_fmap_critical_take(&sockets_fds, fd);
	if (s) {
		uk_refcount_acquire(&s->refcnt);
		uk_fmap_critical_put(&sockets_fds, fd, s);
	}

	return s;
}

static inline void sock_release(struct unimsg_sock *s)
{
	UK_ASSERT(s);

	if (uk_refcount_release(&s->refcnt))
		free(s);
}

int net_init(struct qemu_ivshmem_info control_ivshmem,
	     struct qemu_ivshmem_info sidecar_ivshmem)
{
	struct unimsg_shm_header *shm_hdr = control_ivshmem.addr;

	int rc = listen_sock_init(shm_hdr);
	if (rc) {
		uk_pr_err("Error retrieving listening sockets data: %s\n",
			  strerror(-rc));
		return rc;
	}

	rc = conn_init(shm_hdr);
	if (rc) {
		uk_pr_err("Error retrieving connections data: %s\n",
			  strerror(-rc));
		return rc;
	}

	rc = sidecar_init(sidecar_ivshmem.addr);
	if (rc) {
		uk_pr_err("Error initializing sidecar: %s\n", strerror(-rc));
		return rc;
	}

	gw_backlog = (void *)shm_hdr + shm_hdr->gw_backlog_off;

	vms_info_sz = shm_hdr->vms_info_sz;
	vm_info = (void *)shm_hdr + shm_hdr->vms_info_off;
	rt_buckets = (unsigned *)(vm_info + vms_info_sz);

	local_id = control_ivshmem.doorbell_id;
	local_addr = vm_info[local_id].addr;

	for (int i = 0; i < PORTS_MAP_BUCKETS; i++) {
		UK_INIT_HLIST_HEAD(&ports_map[i].ports);
		uk_spin_init(&ports_map[i].lock);
	}

	sockets_fds.bmap.size = MAX_SOCKETS;
	sockets_fds.bmap.bitmap = bitmap;
	sockets_fds.map = sockets_ptrs;
	uk_fmap_init(&sockets_fds);

	return 0;
}

int _unimsg_socket()
{
	struct unimsg_sock *s = uk_calloc(unimsg_allocator, 1, sizeof(*s));
	if (!s)
		return -ENOMEM;
	uk_refcount_init(&s->refcnt, 1);

	int fd = uk_fmap_put(&sockets_fds, s, 0);
	if (!_FMAP_INRANGE(&sockets_fds, fd)) {
		free(s);
		return -EMFILE;
	}

	return fd;
}

int _unimsg_close(int sockfd)
{
	struct unimsg_sock *s = uk_fmap_take(&sockets_fds, sockfd);
	if (!s)
		return -EBADF;

	/* Release shared memory resources, if present */
	if (s->ls)
		listen_sock_close(s->ls);
	else if (s->conn)
		conn_close(s->conn, s->side);

	if (s->id.lport)
		port_release(s->id.lport);

	sock_release(s);

	return 0;
}

int _unimsg_bind(int sockfd, __u16 port)
{
	if (port == 0)
		return -EINVAL;

	struct unimsg_sock *s = sock_acquire(sockfd);
	if (!s)
		return -EBADF;

	int rc = 0;

	if (s->id.lport) {
		rc = -EINVAL;
		goto done;
	}

	rc = port_acquire(port, 1);
	if (rc)
		goto done;

	s->id.lport = port;

done:
	sock_release(s);
	return rc;
}

int _unimsg_listen(int sockfd)
{
	struct unimsg_sock *s = sock_acquire(sockfd);
	if (!s)
		return -EBADF;

	int rc = 0;

	/* Linux and possibly other operating systems allow to listen on an
	 * unbound socket. The listen() call selects an available port. What is
	 * the point?
	 */
	if (s->id.lport == 0) {
		rc = -EINVAL;
		goto done;
	}

	rc = listen_sock_create(local_addr, s->id.lport, &s->ls);

done:
	sock_release(s);
	return rc;
}

int _unimsg_accept(int sockfd, int nonblock)
{
	int rc;

	struct unimsg_sock *s = sock_acquire(sockfd);
	if (!s)
		return -EBADF;

	struct unimsg_sock *new = uk_calloc(unimsg_allocator, 1, sizeof(*new));
	if (!new) {
		rc = -ENOMEM;
		goto done;
	}

	struct conn *conn;
	rc = listen_sock_recv_conn(s->ls, &conn, nonblock);
	if (rc)
		goto erralloc;

	struct conn_id id = conn_get_id(conn);
	new->id.raddr = id.client_addr;
	new->id.rport = id.client_port;
	new->id.lport = id.server_port;
	new->side = CONN_SIDE_SRV;
	new->conn = conn;

	/* Allocate a new FD */
	uk_refcount_init(&new->refcnt, 1);
	int newfd = uk_fmap_put(&sockets_fds, new, 0);
	if (!_FMAP_INRANGE(&sockets_fds, newfd)) {
		rc = -EMFILE;
		goto errconn;
	}

	/* Refcount the port */
	rc = port_acquire(new->id.lport, 0);
	UK_ASSERT(!rc);

	rc = newfd;
	goto done;

errconn:
	conn_close(conn, CONN_SIDE_SRV);
erralloc:
	free(new);
done:
	sock_release(s);
	return rc;
}

static int connect_to_gw(struct unimsg_sock *s, __u32 addr, __u16 port)
{
	struct conn_id id;
	id.client_id = local_id;
	id.client_addr = local_addr;
	id.client_port = s->id.lport;
	id.server_id = 0;
	id.server_addr = addr;
	id.server_port = port;
	int rc = conn_alloc(&s->conn, &id);
	if (rc)
		return rc;

	unsigned conn_idx = conn_get_idx(s->conn);
	if (unimsg_ring_enqueue(gw_backlog, &conn_idx, 1))
		return -EAGAIN;

	return 0;
}

static int connect_to_peer(struct unimsg_sock *s, __u32 addr, __u16 port,
			   unsigned peer_id)
{
	struct listen_sock *ls;
	int rc = listen_sock_lookup_acquire(addr, port, &ls);
	if (rc)
		return rc;

	struct conn_id id;
	id.client_id = local_id;
	id.client_addr = local_addr;
	id.client_port = s->id.lport;
	id.server_id = peer_id;
	id.server_addr = addr;
	id.server_port = port;
	rc = conn_alloc(&s->conn, &id);
	if (rc)
		goto errls;

	/* TODO: I don't like the decoupling between the listen_sock and the id
	 * of the peer. This info should be bound together
	 */
	rc = listen_sock_send_conn(ls, s->conn, peer_id);
	if (rc)
		goto errconn;

	listen_sock_release(ls);

	return 0;

errconn:
	conn_free(s->conn);
errls:
	listen_sock_release(ls);
	return rc;
}

static int peer_lookup(__u32 addr, unsigned *peer_id)
{
	UK_ASSERT(peer_id);

	unsigned id = rt_buckets[jhash(&addr, sizeof(addr), 0) % vms_info_sz];
	while (id != vms_info_sz) {
		if (vm_info[id].addr == addr)
			break;
		id = vm_info[id].rt_bkt_next;
	}

	if (id == vms_info_sz)
		return -ENOENT;

	*peer_id = id;

	return 0;
}

int _unimsg_connect(int sockfd, __u32 addr, __u16 port)
{
	int rc = 0;

	struct unimsg_sock *s = sock_acquire(sockfd);
	if (!s)
		return -EBADF;

	if (!s->id.lport) {
		rc = port_acquire_new();
		if (rc < 0)
			goto done;
		else
			s->id.lport = rc;
	}

	unsigned peer_id;
	if (peer_lookup(addr, &peer_id))
		rc = connect_to_gw(s, addr, port);
	else
		rc = connect_to_peer(s, addr, port, peer_id);
	if (rc)
		goto done;

	s->id.raddr = addr;
	s->id.rport = port;
	s->side = CONN_SIDE_CLI;

done:
	sock_release(s);
	return rc;
}

int _unimsg_send(int sockfd, struct unimsg_shm_desc *descs, unsigned ndescs,
		 int nonblock)
{
	int rc;

	if (!descs || ndescs > UNIMSG_MAX_DESCS_BULK)
		return -EINVAL;

	struct unimsg_sock *s = sock_acquire(sockfd);
	if (!s)
		return -EBADF;

	if (!s->conn) {
		rc = -ENOTCONN;
		goto done;
	}

	if (ndescs == 0) {
		rc = 0;
		goto done;
	}

	struct unimsg_shm_desc idescs[UNIMSG_MAX_DESCS_BULK];
	memcpy(idescs, descs, ndescs * sizeof(struct unimsg_shm_desc));
#ifdef CONFIG_LIBUNIMSG_MEMORY_PROTECTION
	/* We need to disable buffer access before sending for two reasons:
	 * a. If we just disabled access after a successful send there would
	 *    potentially be a time window in which both sender and receiver
	 *    have access to the buffer
	 * b. Disabling access also checks that the app is not trying to send
	 *    forged descriptors
	 */
	for (unsigned i = 0; i < ndescs; i++)
		set_buffer_access(idescs[i].addr, 0);
#endif

	if (sidecar_tx(idescs, ndescs) == SIDECAR_DROP) {
		/* TODO: find a better return code */
		rc = -EINVAL;

	} else {
		rc = conn_send(s->conn, idescs, ndescs, s->side, nonblock);
	}

#ifdef CONFIG_LIBUNIMSG_MEMORY_PROTECTION
	if (rc) {
		for (unsigned i = 0; i < ndescs; i++)
			set_buffer_access(idescs[i].addr, 1);
	}
#endif

done:
	sock_release(s);
	return rc;
}

int _unimsg_recv(int sockfd, struct unimsg_shm_desc *descs, unsigned *ndescs,
		 int nonblock)
{
	int rc;

	if (!descs || !ndescs)
		return -EINVAL;

	unsigned indescs = *ndescs;
	if (indescs > UNIMSG_MAX_DESCS_BULK)
		return -EINVAL;

	struct unimsg_sock *s = sock_acquire(sockfd);
	if (!s)
		return -EBADF;

	if (!s->conn) {
		rc = -ENOTCONN;
		goto done;
	}

	if (indescs == 0) {
		rc = 0;
		goto done;
	}

	struct unimsg_shm_desc idescs[UNIMSG_MAX_DESCS_BULK];

	rc = conn_recv(s->conn, idescs, &indescs, s->side, nonblock);
	if (rc)
		goto done;

	if (sidecar_rx(idescs, indescs) == SIDECAR_DROP) {
		/* TODO: find a better return code */
		rc = -EINVAL;

	} else {
		for (unsigned i = 0; i < indescs; i++) {
			idescs[i].addr = unimsg_buffer_get_addr(&idescs[i]);
#ifdef CONFIG_LIBUNIMSG_MEMORY_PROTECTION
			set_buffer_access(idescs[i].addr, 1);
#endif
		}
		*ndescs = indescs;
		memcpy(descs, idescs, indescs * sizeof(struct unimsg_shm_desc));
	}

done:
	sock_release(s);
	return rc;
}

int _unimsg_poll(int *sockfds, unsigned nsocks, int *ready)
{
	int rc = 0;
	struct unimsg_sock *socks[UNIMSG_MAX_NSOCKS];

	if (!sockfds || !ready)
		return -EINVAL;

	if (nsocks > UNIMSG_MAX_NSOCKS)
		return -EINVAL;

	for (unsigned i = 0; i < nsocks; i++) {
		socks[i] = sock_acquire(sockfds[i]);
		if (!socks[i]) {
			for (unsigned j = 0; j < i; j++)
				sock_release(socks[j]);
			return -EBADF;
		}
	}
again:
	int done = 0;
	for (unsigned i = 0; i < nsocks; i++) {
		if (!socks[i] || (!socks[i]->conn && !socks[i]->ls)) {
			rc = -EINVAL;
			goto done;
		}

		if (socks[i]->conn) {
			if (conn_poll_check(socks[i]->conn, socks[i]->side)) {
				ready[i] = 1;
				done = 1;
			} else {
				ready[i] = 0;
			}
		} else {
			if (listen_sock_poll_check(socks[i]->ls)) {
				ready[i] = 1;
				done = 1;
			} else {
				ready[i] = 0;
			}
		}
	}

	if (done) {
		rc = 0;
		goto done;
	}

	struct uk_thread *t = uk_thread_current();
	uk_thread_block(t);

	for (unsigned i = 0; i < nsocks; i++) {
		if (socks[i]->conn) {
			if (conn_poll_set(socks[i]->conn, socks[i]->side)) {
				uk_thread_wake(t);
				goto skip;
			}
		} else {
			if (listen_sock_poll_set(socks[i]->ls)) {
				uk_thread_wake(t);
				goto skip;
			}
		}
	}

	uk_sched_yield();

skip:
	int some_ready = 0;
	for (unsigned i = 0; i < nsocks; i++) {
		if (socks[i]->conn) {
			if (conn_poll_clean(socks[i]->conn, socks[i]->side)) {
				ready[i] = 1;
				some_ready = 1;
			}
		} else {
			if (listen_sock_poll_clean(socks[i]->ls)) {
				ready[i] = 1;
				some_ready = 1;
			}
		}
	}

	/* Handle spurious wakeups
	 * TODO:
	 */
	if (!some_ready)
		goto again;

done:
	for (unsigned i = 0; i < nsocks; i++)
		sock_release(socks[i]);
	return rc;
}
