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
	enum conn_dir dir;
};

static __u32 local_addr;
static struct uk_hlist_head sockets_map[SOCKETS_MAP_BUCKETS];
static struct uk_mutex sockets_map_mtx;
static __u16 last_assigned_port = EPHEMERAL_PORTS_FIRST - 1;

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

int sock_init(struct qemu_ivshmem_info ivshmem)
{
	int rc = listen_sock_init((struct unimsg_shm_header *)ivshmem.addr);
	if (rc) {
		uk_pr_err("Error retrieving listening sockets data: %s\n",
			  strerror(-rc));
		return rc;
	}

	rc = conn_init((struct unimsg_shm_header *)ivshmem.addr);
	if (rc) {
		uk_pr_err("Error retrieving connections data: %s\n",
			  strerror(-rc));
		return rc;
	}

	local_addr = ivshmem.doorbell_id;

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
		conn_close(s->conn, s->dir);

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
	new->dir = DIR_SRV_TO_CLI;
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

	struct listen_sock *ls;
	rc = listen_sock_lookup_acquire(addr, port, &ls);
	if (rc)
		return rc;

	struct conn_id id;
	id.client_addr = local_addr;
	id.client_port = s->id.lport;
	id.server_addr = addr;
	id.server_port = port;
	rc = conn_alloc(&s->conn, &id);
	if (rc)
		goto err_release_ls;

	rc = listen_sock_send_conn(ls, s->conn);
	if (rc)
		goto err_free_conn;

	listen_sock_release(ls);

	s->id.raddr = addr;
	s->id.rport = port;
	s->dir = DIR_CLI_TO_SRV;

	/* Move the socket to the proper bucket */
	uk_mutex_lock(&sockets_map_mtx);
	uk_hlist_del(&s->list);
	struct uk_hlist_head *bucket = get_bucket(s->id);
	uk_hlist_add_head(&s->list, bucket);
	uk_mutex_unlock(&sockets_map_mtx);

	return 0;

err_free_conn:
	conn_free(s->conn);
err_release_ls:
	listen_sock_release(ls);
	return rc;
}

int _unimsg_send(struct unimsg_sock *s, struct unimsg_shm_desc *desc,
		 int nonblock)
{
	if (!s || !desc)
		return -EINVAL;

	if (!s->conn)
		return -ENOTCONN;

#ifdef CONFIG_LIBUNIMSG_MEMORY_PROTECTION
	/* TODO: can we just disable access once the send() has succeed? There
	 * might be a short window in which the buffer is technically accessible
	 * by both VMs
	 */
	/* TODO: what to do here? Can setting the access actually fail? */
	int __maybe_unused brc = disable_buffer_access(*desc);
	UK_ASSERT(!brc);
#endif

	int rc = conn_send(s->conn, desc, s->dir, nonblock);
#ifdef CONFIG_LIBUNIMSG_MEMORY_PROTECTION
	if (rc) {
		/* TODO: what to do here? Can setting the access actually
		 * fail?
		 */
		brc = enable_buffer_access(*desc);
		UK_ASSERT(!brc);
	}
#endif

	return rc;
}

int _unimsg_recv(struct unimsg_sock *s, struct unimsg_shm_desc *desc,
		 int nonblock)
{
	if (!s || !desc)
		return -EINVAL;

	if (!s->conn)
		return -ENOTCONN;

	int rc = conn_recv(s->conn, desc, s->dir, nonblock);
#ifdef CONFIG_LIBUNIMSG_MEMORY_PROTECTION
	if (!rc) {
		/* TODO: what to do here? Can setting the access actually
		 * fail?
		 */
		int __maybe_unused brc = enable_buffer_access(*desc);
		UK_ASSERT(!brc);
	}
#endif

	return rc;
}