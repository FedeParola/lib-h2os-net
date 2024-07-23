/*
 * Some sort of Copyright
 */

#ifndef __LIBUNIMSG_SHM__
#define __LIBUNIMSG_SHM__

#include <unimsg/api.h>
#include <uk/arch/types.h>

#define UNIMSG_BUFFER_SIZE 4096
#define UNIMSG_BUFFER_HEADROOM 0
#define UNIMSG_MAX_DESCS_BULK 16

#ifdef __cplusplus
extern "C" {
#endif

struct unimsg_shm_desc {
	void *addr;
	unsigned size;
	unsigned off;
	unsigned idx;
};

void *unimsg_buffer_get_addr(struct unimsg_shm_desc *desc);

/**
 * Resets address, offset and size of a shared memory buffer.
 * @param desc Descriptor of the buffer to reset
 */
void unimsg_buffer_reset(struct unimsg_shm_desc *desc);

UNIMSG_API_DEFINE(unimsg_buffer_get, struct unimsg_shm_desc *, descs,
		  unsigned, ndescs);

UNIMSG_API_DEFINE(unimsg_buffer_put, struct unimsg_shm_desc *, descs,
		  unsigned, ndescs);

/**
 * Put function without buffer ownership change. For internal use only.
 */
int unimsg_buffer_put_internal(struct unimsg_shm_desc *descs, unsigned ndescs);

#ifdef __cplusplus
}
#endif

#endif /* __LIBUNIMSG_SHM__ */
