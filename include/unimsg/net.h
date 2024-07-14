/*
 * Some sort of Copyright
 */

#ifndef __LIBUNIMSG_NET__
#define __LIBUNIMSG_NET__

#include <unimsg/api.h>
#include <unimsg/shm.h>
#include <uk/arch/types.h>

/* Maximum number of sockets that can be passed to the unimsg_poll() call */
#define UNIMSG_MAX_NSOCKS 256

#ifdef __cplusplus
extern "C" {
#endif

/**
 *  Opaque socket structure.
 */
struct unimsg_sock;

/* TODO: exchanging pointers between trusted and untrusted code is dangerous, a
 * malicious/misbehaving application could pass a pointer to a wrong memory
 * region and our safe code would corrupt it. Better to rely on a system like
 * file descriptors. Can we leverage the one of Unikraft? Probably we need to
 * implement an internal one if we want to keep the region of code protected
 * with MPK limited
 */

/**
 * int unimsg_socket(struct unimsg_sock **s)
 *
 * Creates a socket.
 * @param s Socket pointer to populate
 * @return 0 on success, a negative errno value otherwise
 */
UNIMSG_API_DEFINE(unimsg_socket, struct unimsg_sock **, s)

/**
 * int unimsg_close(struct unimsg_sock *s)
 *
 * Closes a socket.
 * @param s Socket to close
 * @return 0 on success, a negative errno value otherwise
 */
UNIMSG_API_DEFINE(unimsg_close, struct unimsg_sock *, s)

/**
 * int unimsg_bind(struct unimsg_sock *s, __u16 port)
 *
 * Binds a socket to the given port, if available.
 * @param s Socket to bind
 * @param port Port to bind to
 * @return 0 on success, a negative errno value otherwise
 */
UNIMSG_API_DEFINE(unimsg_bind, struct unimsg_sock *, s, __u16, port);

/**
 * int unimsg_listen(struct unimsg_sock *s)
 *
 * Enables a socket to listen for incoming connections.
 * @param s Socket to enable
 * @return 0 on success, a negative errno value otherwise
 */
UNIMSG_API_DEFINE(unimsg_listen, struct unimsg_sock *, s);

/**
 * int unimsg_accept(struct unimsg_sock *listening,
 * 		     struct unimsg_sock **connected, int nonblock)
 *
 * Accepts an incoming connection on a listening socket.
 * @param listening Listening socket to receive the connection on
 * @param connected Pointer to the new connected socket to populate
 * @param nonblock Return -EAGAIN immediately if the operation would block
 * @return 0 on success, a negative errno value otherwise
 */
UNIMSG_API_DEFINE(unimsg_accept, struct unimsg_sock *, listening,
		  struct unimsg_sock **, connected, int, nonblock);

/**
 * int unimsg_connect(struct unimsg_sock *s, __u32 addr, __u16 port)
 *
 * Connects a socket to a remote listening socket.
 * @param s Socket to connect
 * @param addr Address of the remote socket
 * @param port Port of the remote socket
 * @return 0 on success, a negative errno value otherwise
 */
UNIMSG_API_DEFINE(unimsg_connect, struct unimsg_sock *, s, __u32, addr,
		  __u16, port);

/**
 * int unimsg_send(struct unimsg_sock *s, struct unimsg_shm_desc *descs,
 * 		   unsigned ndescs, int nonblock)
 *
 * Sends exactly ndescs shm descriptors on a connected socket.
 * @param s Socket to send on
 * @param descs Array of descriptors to send
 * @param ndescs Number of descriptors to send
 * @param nonblock Return -EAGAIN immediately if the operation would block
 * @return 0 on success, a negative errno value otherwise
 */
UNIMSG_API_DEFINE(unimsg_send, struct unimsg_sock *, s, const void *, buf,
		  size_t, len, int, nonblock);

/**
 * int unimsg_recv(struct unimsg_sock *s, struct unimsg_shm_desc *descs,
 * 		   unsigned *ndescs, int nonblock)
 *
 * Receives up to ndescs shm descriptors on a connected socket.
 * @param s Socket to receive on
 * @param descs Array of descriptors to populate
 * @param ndescs Size of the array of descs in input, number of received descs
 * 		 on return
 * @param nonblock Return -EAGAIN immediately if the operation would block
 * @return 0 on success, a negative errno value otherwise. In case of success
 * 	   ndescs is guaranteed to be > 0
 */
UNIMSG_API_DEFINE(unimsg_recv, struct unimsg_sock *, s, void *, buf,
		  size_t *, len, int, nonblock);

/**
 * int _unimsg_poll(struct unimsg_sock **socks, unsigned nsocks, int *active)
 *
 * Checks whether a group of sockets is ready to accept a connection or receive
 * data. Blocks until at least one socket is ready.
 * @param socks Array of sockets to check
 * @param nsocks Size of the array
 * @param ready Array of integer flags, each flag is set to 1 on return if the
 * 		corresponding socket is ready
 * @return 0 on success, a negative errno value otherwise
 */
UNIMSG_API_DEFINE(unimsg_poll, struct unimsg_sock **, socks, unsigned, nsocks,
		  int *, ready);

#ifdef __cplusplus
}
#endif

#endif /* __LIBUNIMSG_NET__ */
