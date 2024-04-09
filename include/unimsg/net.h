/*
 * Some sort of Copyright
 */

#ifndef __LIBUNIMSG_NET__
#define __LIBUNIMSG_NET__

#include <unimsg/api.h>
#include <unimsg/shm.h>
#include <uk/arch/types.h>

/* At the moment unimsg uses a separate pool of File Descriptors for its
 * sockets, hence Unikraft functions don't work on these FDs.
 * TODO: integrate with Unikraft FDs system.
 */

/* Maximum number of sockets that can be passed to the unimsg_poll() call */
#define UNIMSG_MAX_NSOCKS 256

#ifdef __cplusplus
extern "C" {
#endif

/**
 * int unimsg_socket()
 *
 * Creates a socket.
 * @return A file descriptor for the new socket on success, a negative errno
 * 	   value otherwise
 */
UNIMSG_API_DEFINE(unimsg_socket)

/**
 * int unimsg_close(int sockfd)
 *
 * Closes a socket.
 * @param sockfd Socket to close
 * @return 0 on success, a negative errno value otherwise
 */
UNIMSG_API_DEFINE(unimsg_close, int, sockfd)

/**
 * int unimsg_bind(int sockfd, __u16 port)
 *
 * Binds a socket to the given port, if available.
 * @param sockfd Socket to bind
 * @param port Port to bind to
 * @return 0 on success, a negative errno value otherwise
 */
UNIMSG_API_DEFINE(unimsg_bind, int, sockfd, __u16, port);

/**
 * int unimsg_listen(int sockfd)
 *
 * Enables a socket to listen for incoming connections.
 * @param sockfd Socket to enable
 * @return 0 on success, a negative errno value otherwise
 */
UNIMSG_API_DEFINE(unimsg_listen, int, sockfd);

/**
 * int unimsg_accept(int sockfd, int nonblock)
 *
 * Accepts an incoming connection on a listening socket.
 * @param sockfd Listening socket to receive the connection on
 * @param nonblock Return -EAGAIN immediately if the operation would block
 * @return A file descriptor for the new connected socket on success, a negative
 * 	   errno value otherwise
 */
UNIMSG_API_DEFINE(unimsg_accept, int, sockfd, int, nonblock);

/**
 * int unimsg_connect(int sockfd, __u32 addr, __u16 port)
 *
 * Connects a socket to a remote listening socket.
 * @param sockfd Socket to connect
 * @param addr Address of the remote socket
 * @param port Port of the remote socket
 * @return 0 on success, a negative errno value otherwise
 */
UNIMSG_API_DEFINE(unimsg_connect, int, sockfd, __u32, addr, __u16, port);

/**
 * int unimsg_send(int sockfd, struct unimsg_shm_desc *descs, unsigned ndescs,
 * 		   int nonblock)
 *
 * Sends exactly ndescs shm descriptors on a connected socket.
 * @param sockfd Socket to send on
 * @param descs Array of descriptors to send
 * @param ndescs Number of descriptors to send
 * @param nonblock Return -EAGAIN immediately if the operation would block
 * @return 0 on success, a negative errno value otherwise
 */
UNIMSG_API_DEFINE(unimsg_send, int, sockfd, struct unimsg_shm_desc *, descs,
		  unsigned, ndescs, int, nonblock);

/**
 * int unimsg_recv(int sockfd, struct unimsg_shm_desc *descs, unsigned *ndescs,
 * 		   int nonblock)
 *
 * Receives up to ndescs shm descriptors on a connected socket.
 * @param sockfd Socket to receive on
 * @param descs Array of descriptors to populate
 * @param ndescs Size of the array of descs in input, number of received descs
 * 		 on return
 * @param nonblock Return -EAGAIN immediately if the operation would block
 * @return 0 on success, a negative errno value otherwise. In case of success
 * 	   ndescs is guaranteed to be > 0
 */
UNIMSG_API_DEFINE(unimsg_recv, int, sockfd, struct unimsg_shm_desc *, desc,
		  unsigned *, ndescs, int, nonblock);

/**
 * int _unimsg_poll(int *socks, unsigned nsocks, int *active)
 *
 * Checks whether a group of sockets is ready to accept a connection or receive
 * data. Blocks until at least one socket is ready.
 * @param sockfdocks Array of sockets to check
 * @param nsocks Size of the array
 * @param ready Array of integer flags, each flag is set to 1 on return if the
 * 		corresponding socket is ready
 * @return 0 on success, a negative errno value otherwise
 */
UNIMSG_API_DEFINE(unimsg_poll, int *, socks, unsigned, nsocks, int *, ready);

#ifdef __cplusplus
}
#endif

#endif /* __LIBUNIMSG_NET__ */
