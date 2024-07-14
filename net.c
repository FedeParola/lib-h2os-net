/*
 * Some sort of Copyright
 */

#include <unimsg/net.h>
#include <uk/mutex.h>
#include <ivshmem.h>
#include <uk/print.h>
#include <string.h>
#include "common.h"
#include "connection.h"
#include "listen_sock.h"
#include "jhash.h"
#include "ring.h"
#include "sidecar.h"

#define SOCKETS_MAP_BUCKETS 64
#define EPHEMERAL_PORTS_FIRST 1024
#define EPHEMERAL_PORTS_COUNT (0xffff - EPHEMERAL_PORTS_FIRST + 1)

struct socket_id {
	__u32 raddr;
	__u16 rport;
	__u16 lport; /* 0 if socket not bound */
};

struct unimsg_sock {
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

static unsigned local_id;
static __u32 local_addr;
static struct uk_hlist_head sockets_map[SOCKETS_MAP_BUCKETS];
static struct uk_mutex sockets_map_mtx;
static __u16 last_assigned_port = EPHEMERAL_PORTS_FIRST - 1;
static struct unimsg_ring *gw_backlog;
static unsigned long vms_info_sz;
static struct vm_info *vm_info;
static unsigned *rt_buckets;

/* Helpers to access the sockets hash map */

static inline struct uk_hlist_head *get_bucket(struct socket_id id)
{
	return &sockets_map[jhash(&id, sizeof(id), 0) % SOCKETS_MAP_BUCKETS];
}

static inline
struct unimsg_sock *bucket_get_socket(struct socket_id id,
				      struct uk_hlist_head *bucket)
{
	struct unimsg_sock *sock;
	struct uk_hlist_node *next;

	uk_hlist_for_each_entry_safe(sock, next, bucket, list) {
		if (!memcmp(&sock->id, &id, sizeof(id)))
			return sock;
	}

	return NULL;
}

static inline struct unimsg_sock *get_socket(struct socket_id id)
{
	return bucket_get_socket(id, get_bucket(id));
}

int net_init(struct qemu_ivshmem_info ivshmem)
{
	struct unimsg_shm_header *shm_hdr = ivshmem.addr;

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

	gw_backlog = (void *)shm_hdr + shm_hdr->gw_backlog_off;

	vms_info_sz = shm_hdr->vms_info_sz;
	vm_info = (void *)shm_hdr + shm_hdr->vms_info_off;
	rt_buckets = (unsigned *)(vm_info + vms_info_sz);

	local_id = ivshmem.doorbell_id;
	local_addr = vm_info[local_id].addr;

	for (int i = 0; i < SOCKETS_MAP_BUCKETS; i++)
		UK_INIT_HLIST_HEAD(&sockets_map[i]);

	uk_mutex_init(&sockets_map_mtx);

	return 0;
}

int _unimsg_socket(struct unimsg_sock **s)
{
	if (!s)
		return -EINVAL;

	*s = uk_calloc(unimsg_allocator, 1, sizeof(**s));
	if (!s)
		return -ENOMEM;

	return 0;
}

int _unimsg_close(struct unimsg_sock *s)
{
	if (!s)
		return -EINVAL;

	/* Release shared memory resources, if present */
	if (s->ls)
		listen_sock_close(s->ls);
	else if (s->conn)
		conn_close(s->conn, s->side);

	/* Remove the socket form the sockets_map map if present. A socket is
	 * stored for sure if it is bound to a local port
	 */
	if (s->id.lport) {
		uk_mutex_lock(&sockets_map_mtx);
		uk_hlist_del(&s->list);
		uk_mutex_unlock(&sockets_map_mtx);
	}

	/* It's up to the application to guarantee that no other reference to
	 * the socket exists
	 */
	uk_free(unimsg_allocator, s);

	return 0;
}

int _unimsg_bind(struct unimsg_sock *s, __u16 port)
{
	if (!s || port == 0)
		return -EINVAL;

	if (s->id.lport)
		return -EINVAL;
	s->id.lport = port;

	struct uk_hlist_head *bucket = get_bucket(s->id);

	uk_mutex_lock(&sockets_map_mtx);

	if (bucket_get_socket(s->id, bucket)) {
		uk_mutex_unlock(&sockets_map_mtx);
		s->id.lport = 0;
		return -EADDRINUSE;
	}

	uk_hlist_add_head(&s->list, bucket);
	uk_mutex_unlock(&sockets_map_mtx);

	return 0;
}

int _unimsg_listen(struct unimsg_sock *s)
{
	/* Linux and possibly other operating systems allow to listen on an
	 * unbound socket. The listen() call selects an available port. What is
	 * the point?
	 */
	if (!s || s->id.lport == 0)
		return -EINVAL;

	return listen_sock_create(local_addr, s->id.lport, &s->ls);
}

int _unimsg_accept(struct unimsg_sock *listening,
		   struct unimsg_sock **connected, int nonblock)
{
	if (!listening || !connected)
		return -EINVAL;

	struct unimsg_sock *new = uk_calloc(unimsg_allocator, 1, sizeof(*new));
	if (!new)
		return -ENOMEM;

	struct conn *conn;
	int rc = listen_sock_recv_conn(listening->ls, &conn, nonblock);
	if (rc) {
		uk_free(unimsg_allocator, new);
		return rc;
	}

	struct conn_id id = conn_get_id(conn);
	new->id.raddr = id.client_addr;
	new->id.rport = id.client_port;
	new->id.lport = id.server_port;
	new->side = CONN_SIDE_SRV;
	new->conn = conn;

	/* Add the socket to the local map */
	struct uk_hlist_head *bucket = get_bucket(new->id);
	uk_mutex_lock(&sockets_map_mtx);
	uk_hlist_add_head(&new->list, bucket);
	uk_mutex_unlock(&sockets_map_mtx);

	*connected = new;

	return 0;
}

/* Super dummy algorithm
 * Could block all other bind/close for a long time if it cannot find a port
 */
static int assign_local_port(struct unimsg_sock *s)
{
	UK_ASSERT(s);

	uk_mutex_lock(&sockets_map_mtx);
	for (int i = EPHEMERAL_PORTS_COUNT; i > 0; i--) {
		s->id.lport = ++last_assigned_port;

		struct uk_hlist_head *bucket = get_bucket(s->id);
		if (!bucket_get_socket(s->id, bucket)) {
			uk_hlist_add_head(&s->list, bucket);
			uk_mutex_unlock(&sockets_map_mtx);
			return 0;
		}

		/* Wrap */
		if (last_assigned_port == 0)
			last_assigned_port = EPHEMERAL_PORTS_FIRST - 1;
	}

	s->id.lport = 0;
	return -EADDRINUSE;
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
		goto err_release_ls;

	/* TODO: I don't like the decoupling between the listen_sock and the id
	 * of the peer. This info should be bound together
	 */
	rc = listen_sock_send_conn(ls, s->conn, peer_id);
	if (rc)
		goto err_free_conn;

	listen_sock_release(ls);

	return 0;

err_free_conn:
	conn_free(s->conn);
err_release_ls:
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

int _unimsg_connect(struct unimsg_sock *s, __u32 addr, __u16 port)
{
	if (!s)
		return -EINVAL;

	int rc = 0;
	if (!s->id.lport) {
		rc = assign_local_port(s);
		if (rc)
			return rc;
	}

	unsigned peer_id;
	if (peer_lookup(addr, &peer_id))
		rc = connect_to_gw(s, addr, port);
	else
		rc = connect_to_peer(s, addr, port, peer_id);
	if (rc)
		return rc;

	s->id.raddr = addr;
	s->id.rport = port;
	s->side = CONN_SIDE_CLI;

	/* Move the socket to the proper bucket */
	uk_mutex_lock(&sockets_map_mtx);
	uk_hlist_del(&s->list);
	struct uk_hlist_head *bucket = get_bucket(s->id);
	uk_hlist_add_head(&s->list, bucket);
	uk_mutex_unlock(&sockets_map_mtx);

	return 0;
}

int _unimsg_send(struct unimsg_sock *s, const void *buf, size_t len,
		 int nonblock)
{
	if (!s || !buf)
		return -EINVAL;

	if (!s->conn)
		return -ENOTCONN;

	if (len == 0)
		return 0;

	struct unimsg_shm_desc descs[UNIMSG_MAX_DESCS_BULK];
	unsigned ndescs = (len - 1) / UNIMSG_BUFFER_SIZE + 1;
	int rc = _unimsg_buffer_get(descs, ndescs);
	if (rc)
		return rc;

	const void *pos = buf;
	size_t left = len;
	unsigned i;
	for (i = 0; i < ndescs - 1; i++) {
		memcpy(descs[i].addr, pos, UNIMSG_BUFFER_SIZE);
		descs[i].size = UNIMSG_BUFFER_SIZE;
		pos += UNIMSG_BUFFER_SIZE;
		left -= UNIMSG_BUFFER_SIZE;
	}
	memcpy(descs[i].addr, pos, left);
	descs[i].size = left;

	if (sidecar_tx(descs, ndescs) == SIDECAR_DROP) {
		_unimsg_buffer_put(descs, ndescs);
		/* TODO: find a better return code */
		rc = -EINVAL;
	} else {
		rc = conn_send(s->conn, descs, ndescs, s->side, nonblock);
	}

	return rc;
}

int _unimsg_recv(struct unimsg_sock *s, void *buf, size_t *len, int nonblock)
{
	if (!s || !buf || !len)
		return -EINVAL;

	if (!s->conn)
		return -ENOTCONN;

	if (len == 0)
		return 0;

	struct unimsg_shm_desc descs[UNIMSG_MAX_DESCS_BULK];
	unsigned ndescs = UNIMSG_MAX_DESCS_BULK;
	int rc = conn_recv(s->conn, descs, &ndescs, s->side, nonblock);
	if (rc)
		return rc;

	if (sidecar_rx(descs, ndescs) == SIDECAR_DROP) {
		/* TODO: find a better return code */
		rc = -EINVAL;

	} else {
		*len = 0;
		void *pos = buf;
		for (unsigned i = 0; i < ndescs; i++) {
			memcpy(pos, descs[i].addr, descs[i].size);
			pos += descs[i].size;
			*len += descs[i].size;
		}
	}

	_unimsg_buffer_put(descs, ndescs);

	return rc;
}

int _unimsg_poll(struct unimsg_sock **socks, unsigned nsocks, int *ready)
{
	if (!socks || !ready)
		return -EINVAL;

	if (nsocks > UNIMSG_MAX_NSOCKS)
		return -EINVAL;

again:;
	int done = 0;
	for (unsigned i = 0; i < nsocks; i++) {
		if (!socks[i] || (!socks[i]->conn && !socks[i]->ls))
			return -EINVAL;

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

	if (done)
		return 0;

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

skip:;
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

	return 0;
}
