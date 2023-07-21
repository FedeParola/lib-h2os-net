/*
 * Some sort of Copyright
 */

#ifndef __LIBUNIMSG_NET__
#define __LIBUNIMSG_NET__

#include <unimsg/api.h>
#include <unimsg/shm.h>
#include <uk/arch/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 *  Opaque socket structure.
 */
struct unimsg_sock;

/**
 * Type of a socket.
 */
enum unimsg_sock_type {
	UNIMSG_SOCK_CONNECTED,
	UNIMSG_SOCK_CONNLESS
};

/* TODO: exchanging pointers between trusted and untrusted code is dangerous, a
 * malicious/misbehaving application could pass a pointer to a wrong memory
 * region and our safe code would corrupt it. Better to rely on a system like
 * file descriptors. Can we leverage the one of Unikraft? Probably we need to
 * implement an internal one if we want to keep the region of code protected
 * with MPK limited
 */

/**
 * int unimsg_sock_create(struct unimsg_sock **s, enum unimsg_sock_type type,
 *			  int nonblock)
 * 
 * Creates a socket.
 * @param s Socket pointer to populate
 * @param type Type of the new socket (connected or connectionless)
 * @param nonblock Whether operations on the socket should be non-blocking
 * @return 0 on success, a negative errno value otherwise
 */
UNIMSG_API_DEFINE(unimsg_sock_create, struct unimsg_sock **, s,
		  enum unimsg_sock_type, type, int, nonblock)

/**
 * int unimsg_sock_close(struct unimsg_sock *s)
 * 
 * Closes a socket.
 * @param s Socket to close
 * @return 0 on success, a negative errno value otherwise
 */
UNIMSG_API_DEFINE(unimsg_sock_close, struct unimsg_sock *, s)

/**
 * int unimsg_sock_bind(struct unimsg_sock *s, __u16 port)
 * 
 * Binds a socket to the given port, if available.
 * @param s Socket to bind
 * @param port Port to bind to
 * @return 0 on success, a negative errno value otherwise
 */
UNIMSG_API_DEFINE(unimsg_sock_bind, struct unimsg_sock *, s, __u16, port);

/**
 * int unimsg_sock_listen(struct unimsg_sock *s)
 * 
 * Enables a socket to listen for incoming connections.
 * @param s Socket to enable
 * @return 0 on success, a negative errno value otherwise
 */
UNIMSG_API_DEFINE(unimsg_sock_listen, struct unimsg_sock *, s);

/**
 * int unimsg_sock_accept(struct unimsg_sock *listening,
 * 			  struct unimsg_sock **connected)
 * 
 * Accepts an incoming connection on a listening socket.
 * @param listening Listening socket to receive the connection on
 * @param connected Pointer to the new connected socket to populate
 * @return 0 on success, a negative errno value otherwise
 */
UNIMSG_API_DEFINE(unimsg_sock_accept, struct unimsg_sock *, listening,
		  struct unimsg_sock **, connected);

/**
 * int unimsg_sock_connect(struct unimsg_sock *s, __u32 addr, __u16 port)
 * 
 * Connects a socket to a remote listening socket.
 * @param s Socket to connect
 * @param addr Address of the remote socket
 * @param port Port of the remote socket
 * @return 0 on success, a negative errno value otherwise
 */
UNIMSG_API_DEFINE(unimsg_sock_connect, struct unimsg_sock *, s, __u32, addr,
		  __u16, port);

/**
 * int unimsg_sock_send(struct unimsg_sock *s, struct unimsg_shm_desc desc)
 * 
 * Sends a shm descriptor on a connected socket.
 * @param s Socket to send on
 * @param desc Descriptor to send
 * @return 0 on success, a negative errno value otherwise
 */
UNIMSG_API_DEFINE(unimsg_sock_send, struct unimsg_sock *, s,
		  struct unimsg_shm_desc *, desc);

/**
 * int unimsg_sock_recv(struct unimsg_sock *s, struct unimsg_shm_desc *desc)
 * 
 * Receives a shm descriptor on a connected socket.
 * @param s Socket to receive on
 * @param desc Descriptor to populate 
 * @return 0 on success, a negative errno value otherwise
 */
UNIMSG_API_DEFINE(unimsg_sock_recv, struct unimsg_sock *, s,
		  struct unimsg_shm_desc *, desc);

#ifdef __cplusplus
}
#endif

#endif /* __LIBUNIMSG_NET__ */