/*
 * Some sort of Copyright
 */

#include <unimsg/net.h>
#include <uk/mutex.h>
#include <uk/plat/qemu/ivshmem.h>
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

struct route {
	__u32 addr;
	unsigned peer_id;
};

static unsigned local_id;
static __u32 local_addr;
static struct uk_hlist_head sockets_map[SOCKETS_MAP_BUCKETS];
static struct uk_mutex sockets_map_mtx;
static __u16 last_assigned_port = EPHEMERAL_PORTS_FIRST - 1;
static struct unimsg_ring *gw_backlog;
static struct route *routes;
static unsigned long rt_sz;

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

	local_id = control_ivshmem.doorbell_id;
	/* TODO: find a way to get addr */
	local_addr = local_id;

	gw_backlog = (void *)shm_hdr + shm_hdr->gw_backlog_off;

	routes = (void *)shm_hdr + shm_hdr->rt_off;
	rt_sz = shm_hdr->rt_sz;

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

	rc = listen_sock_send_conn(ls, s->conn);
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

	/* TODO: replace with hash lookup */
	unsigned peer_id = routes[addr % rt_sz].peer_id;
	if (!peer_id)
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

int _unimsg_send(struct unimsg_sock *s, struct unimsg_shm_desc *descs,
		 unsigned ndescs, int nonblock)
{
	int rc;

	if (!s || !descs || ndescs > UNIMSG_MAX_DESCS_BULK)
		return -EINVAL;

	if (!s->conn)
		return -ENOTCONN;

	if (ndescs == 0)
		return 0;

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

	return rc;
}

int _unimsg_recv(struct unimsg_sock *s, struct unimsg_shm_desc *descs,
		 unsigned *ndescs, int nonblock)
{
	if (!s || !descs || !ndescs)
		return -EINVAL;

	unsigned indescs = *ndescs;
	if (indescs > UNIMSG_MAX_DESCS_BULK)
		return -EINVAL;

	if (!s->conn)
		return -ENOTCONN;

	if (indescs == 0)
		return 0;

	struct unimsg_shm_desc idescs[UNIMSG_MAX_DESCS_BULK];

	int rc = conn_recv(s->conn, idescs, &indescs, s->side, nonblock);
	if (rc)
		return rc;

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

	return rc;
}