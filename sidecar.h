/*
 * Some sort of Copyright
 */

#ifndef __LIBUNIMSG_SIDECAR__
#define __LIBUNIMSG_SIDECAR__

#include <unimsg/shm.h>

#define SIDECAR_MAX_FILTERS 16

enum sidecar_verdict {
	SIDECAR_OK,
	SIDECAR_DROP,
};

enum sidecar_filter {
	SIDECAR_FILTER_END,
	REQUEST_LOG_HANDLER,
	HTTP_SPAN_MIDDLEWARE,
	REQUEST_METRIC_HANDLER,
	NEW_TIMEOUT_HANDLER,
	FORWARD_SHIM_HANDLER,
	PROXY_HANDLER,
	REQUEST_APP_METRIC_HANDLER,
	CONCURRENCY_STATE_HANDLER,
	SIDECAR_FILTER_MAX,
};

struct sidecar_config {
	int rx_filetrs_chain[SIDECAR_MAX_FILTERS];
	int tx_filetrs_chain[SIDECAR_MAX_FILTERS];
};

struct sidecar_stats {
	unsigned long request_count;
	unsigned long response_time_ms;
	unsigned long app_request_count;
	unsigned long app_response_time_ms;
	unsigned long queue_depth;
};

struct sidecar_shm {
	struct sidecar_config config;
	struct sidecar_stats stats;
};

typedef enum sidecar_verdict (*filter_t)(struct unimsg_shm_desc *descs,
				         unsigned ndescs);

int sidecar_init(struct qemu_ivshmem_info ivshmem, int enable);

enum sidecar_verdict sidecar_tx(struct unimsg_shm_desc *descs, unsigned ndescs);

enum sidecar_verdict sidecar_rx(struct unimsg_shm_desc *descs, unsigned ndescs);

#endif /* __LIBUNIMSG_SIDECAR__ */
