/*
 * Some sort of Copyright
 */

#include <h2os/net.h>
#include <uk/init.h>
#include <uk/mutex.h>
#include <uk/plat/qemu/ivshmem.h>
#include <uk/print.h>
#include <string.h>
#include "common.h"
#include "conn_sock.h"
#include "listen_sock.h"
#include "jhash.h"

#define SOCKETS_MAP_BUCKETS 64
#define EPHEMERAL_PORTS_FIRST 1024
#define EPHEMERAL_PORTS_COUNT (0xffff - EPHEMERAL_PORTS_FIRST + 1)

struct socket_id { 
	__u32 raddr;
	__u16 rport;
	__u16 lport; /* 0 if socket not bound */
	enum h2os_sock_type type;
};

struct h2os_sock {
	struct uk_hlist_node list;
	struct socket_id id;
	struct listen_sock *ls;
	struct conn_sock *cs;
	int nonblock;
	enum conn_sock_dir dir;
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
struct h2os_sock *bucket_get_socket(struct socket_id id,
				    struct uk_hlist_head *bucket)
{
	struct h2os_sock *sock;
	struct uk_hlist_node *next;

	uk_hlist_for_each_entry_safe(sock, next, bucket, list) {
		if (!memcmp(&sock->id, &id, sizeof(id)))
			return sock;
	}

	return NULL;
}

static inline struct h2os_sock *get_socket(struct socket_id id)
{
	return bucket_get_socket(id, get_bucket(id));
}

static int h2os_net_init()
{
	uk_pr_info("Initialize H2OS networking stack...\n");

	struct qemu_ivshmem_info ivshmem_info;
	int rc = qemu_ivshmem_get_info(IVSHMEM_DEVICE_ID, &ivshmem_info);
	if (rc) {
		uk_pr_err("Error retrieving shared memory infos: %s\n",
			  strerror(-rc));
		return rc;
	}

	if (ivshmem_info.type != QEMU_IVSHMEM_TYPE_DOORBELL) {
		uk_pr_err("Unexpected QEMU ivshmem device type\n");
		return -EINVAL;
	}

	rc = listen_sock_init((struct h2os_shm_header *)ivshmem_info.addr);
	if (rc) {
		uk_pr_err("Error retrieving listening sockets data: %s\n",
			  strerror(-rc));
		return rc;
	}

	rc = conn_sock_init((struct h2os_shm_header *)ivshmem_info.addr);
	if (rc) {
		uk_pr_err("Error retrieving connected sockets data: %s\n",
			  strerror(-rc));
		return rc;
	}

	local_addr = ivshmem_info.doorbell_id;

	for (int i = 0; i < SOCKETS_MAP_BUCKETS; i++)
		UK_INIT_HLIST_HEAD(&sockets_map[i]);

	uk_mutex_init(&sockets_map_mtx);

	return 0;
}
uk_lib_initcall(h2os_net_init);

int h2os_sock_create(struct h2os_sock **s, enum h2os_sock_type type,
		     int nonblock)
{
	if (!s)
		return -EINVAL;

	*s = uk_calloc(uk_alloc_get_default(), 1, sizeof(**s));
	if (!s)
		return -ENOMEM;

	(*s)->id.type = type;
	(*s)->nonblock = nonblock;

	return 0;
}

int h2os_sock_close(struct h2os_sock *s)
{
	if (!s)
		return -EINVAL;

	/* Release shared memory resources, if present */
	if (s->ls)
		listen_sock_close(s->ls);
	else if (s->cs)
		conn_sock_close(s->cs, s->dir);

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
	uk_free(uk_alloc_get_default(), s);

	return 0;
}

int h2os_sock_bind(struct h2os_sock *s, __u16 port)
{
	if (!s || port == 0 || s->id.lport)
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

int h2os_sock_listen(struct h2os_sock *s)
{
	/* Linux and possibly other operating systems allow to listen on an
	 * unbound socket. The listen() call selects an available port. What is
	 * the point?
	 */
	if (!s || s->id.lport == 0)
		return -EINVAL;

	int rc = listen_sock_create(local_addr, s->id.lport, &s->ls);
	if (rc)
		return rc;
	
	return 0;
}

int h2os_sock_accept(struct h2os_sock *listening, struct h2os_sock **connected)
{
	if (!listening || !connected)
		return -EINVAL;

	struct h2os_sock *new = uk_calloc(uk_alloc_get_default(), 1,
					  sizeof(*new));
	if (!new)
		return -ENOMEM;

	struct conn_sock *cs;
	int rc = listen_sock_recv_conn(listening->ls, &cs, listening->nonblock);
	if (rc) {
		uk_free(uk_alloc_get_default(), new);
		return rc;
	}

	struct conn_sock_id id = conn_sock_get_id(cs);
	new->id.raddr = id.client_addr;
	new->id.rport = id.client_port;
	new->id.lport = id.server_port;
	new->id.type = listening->id.type;
	new->nonblock = listening->nonblock;
	new->dir = DIR_SRV_TO_CLI;
	new->cs = cs;

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
static int assign_local_port(struct h2os_sock *s)
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

int h2os_sock_connect(struct h2os_sock *s, __u32 addr, __u16 port)
{
	int rc;

	if (!s)
		return -EINVAL;

	if (!s->id.lport) {
		rc = assign_local_port(s);
		if (rc)
			return rc;
	}

	struct listen_sock *ls;
	rc = listen_sock_lookup_acquire(addr, port, &ls);
	if (rc)
		return rc;

	struct conn_sock_id id;
	id.client_addr = local_addr;
	id.client_port = s->id.lport;
	id.server_addr = addr;
	id.server_port = port;
	rc = conn_sock_alloc(&s->cs, &id);
	if (rc)
		goto err_release_ls;

	rc = listen_sock_send_conn(ls, s->cs);
	if (rc)
		goto err_free_cs;

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

err_free_cs:
	conn_sock_free(s->cs);
err_release_ls:
	listen_sock_release(ls);
	return rc;
}

int h2os_sock_send(struct h2os_sock *s, struct h2os_shm_desc desc)
{
	if (!s)
		return -EINVAL;
	if (!s->cs)
		return -ENOTCONN;

	return conn_sock_send(s->cs, &desc, s->dir, s->nonblock);
}

int h2os_sock_recv(struct h2os_sock *s, struct h2os_shm_desc *desc)
{
	if (!s || !desc)
		return -EINVAL;
	if (!s->cs)
		return -ENOTCONN;

	return conn_sock_recv(s->cs, desc, s->dir, s->nonblock);
}