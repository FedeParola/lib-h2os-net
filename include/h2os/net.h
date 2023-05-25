/*
 * Some sort of Copyright
 */

#ifndef __LIBH2OS_NET__
#define __LIBH2OS_NET__

#include <h2os/api.h>
#include <h2os/shm.h>
#include <uk/arch/types.h>

/**
 *  Opaque socket structure.
 */
struct h2os_sock;

/**
 * Type of a socket.
 */
enum h2os_sock_type {
	H2OS_SOCK_CONNECTED,
	H2OS_SOCK_CONNLESS
};

/* Exchanging pointers between trusted and untrusted code is dangerous, a
 * malicious/misbehaving application could pass a pointer to a wrong memory
 * region and our safe code would corrupt it. Better to rely on a system like
 * file descriptors. Can we leverage the one of Unikraft? Probably we need to
 * implement an internal one if we want to keep the region of code protected
 * with MPK limited
 */

/**
 * int h2os_sock_create(struct h2os_sock **s, enum h2os_sock_type type,
 *			int nonblock)
 * 
 * Creates a socket.
 * @param s Socket pointer to populate
 * @param type Type of the new socket (connected or connectionless)
 * @param nonblock Whether operations on the socket should be non-blocking
 * @return 0 on success, a negative errno value otherwise
 */
H2OS_API_DEFINE(h2os_sock_create, struct h2os_sock **, s,
		enum h2os_sock_type, type, int, nonblock)

/**
 * int h2os_sock_close(struct h2os_sock *s)
 * 
 * Closes a socket.
 * @param s Socket to close
 * @return 0 on success, a negative errno value otherwise
 */
H2OS_API_DEFINE(h2os_sock_close, struct h2os_sock *, s)

/**
 * int h2os_sock_bind(struct h2os_sock *s, __u16 port)
 * 
 * Binds a socket to the given port, if available.
 * @param s Socket to bind
 * @param port Port to bind to
 * @return 0 on success, a negative errno value otherwise
 */
H2OS_API_DEFINE(h2os_sock_bind, struct h2os_sock *, s, __u16, port);

/**
 * int h2os_sock_listen(struct h2os_sock *s)
 * 
 * Enables a socket to listen for incoming connections.
 * @param s Socket to enable
 * @return 0 on success, a negative errno value otherwise
 */
H2OS_API_DEFINE(h2os_sock_listen, struct h2os_sock *, s);

/**
 * int h2os_sock_accept(struct h2os_sock *listening,
 * 			struct h2os_sock **connected)
 * 
 * Accepts an incoming connection on a listening socket.
 * @param listening Listening socket to receive the connection on
 * @param connected Pointer to the new connected socket to populate
 * @return 0 on success, a negative errno value otherwise
 */
H2OS_API_DEFINE(h2os_sock_accept, struct h2os_sock *, listening,
		struct h2os_sock **, connected);

/**
 * int h2os_sock_connect(struct h2os_sock *s, __u32 addr, __u16 port)
 * 
 * Connects a socket to a remote listening socket.
 * @param s Socket to connect
 * @param addr Address of the remote socket
 * @param port Port of the remote socket
 * @return 0 on success, a negative errno value otherwise
 */
H2OS_API_DEFINE(h2os_sock_connect, struct h2os_sock *, s, __u32, addr,
		__u16, port);

/**
 * int h2os_sock_send(struct h2os_sock *s, struct h2os_shm_desc desc)
 * 
 * Sends a shm descriptor on a connected socket.
 * @param s Socket to send on
 * @param desc Descriptor to send
 * @return 0 on success, a negative errno value otherwise
 */
H2OS_API_DEFINE(h2os_sock_send, struct h2os_sock *, s,
		struct h2os_shm_desc *, desc);

/**
 * int h2os_sock_recv(struct h2os_sock *s, struct h2os_shm_desc *desc)
 * 
 * Receives a shm descriptor on a connected socket.
 * @param s Socket to receive on
 * @param desc Descriptor to populate 
 * @return 0 on success, a negative errno value otherwise
 */
H2OS_API_DEFINE(h2os_sock_recv, struct h2os_sock *, s,
		struct h2os_shm_desc *, desc);

#endif /* __LIBH2OS_NET__ */