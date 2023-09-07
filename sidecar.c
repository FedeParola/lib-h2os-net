/*
 * Some sort of Copyright
 */

#include <string.h>
#include <uk/plat/time.h>
#include "sidecar.h"

static struct sidecar_config *config;
static struct sidecar_stats *stats;
struct ewma {
	double alpha;		  /* Weighting factor (0 < alpha < 1) */
	unsigned long ema;	  /* Exponentially Weighted Moving Average */
	unsigned long ingress_ts; /* Use to cache the start timestamp */
	int initialized;	  /* EMA has been initialized */
};
/* TODO: make them per-socket structures */
static struct ewma response_time_ewma;
static struct ewma app_response_time_ewma;

static unsigned long get_time_ms()
{
	return ukplat_monotonic_clock() / 1000000;
}

static unsigned long ewma_update(struct ewma *ewma, unsigned long val)
{
	if (!ewma->initialized) {
		ewma->ema = val;
		ewma->initialized = 1;
	} else {
		ewma->ema = (1.0 - ewma->alpha) * ewma->ema + ewma->alpha * val;
	}

	return ewma->ema;
}

/* Filters forward declarations */
/* Rx filters */
enum sidecar_verdict
request_log_handler(struct unimsg_shm_desc *descs __unused,
		    unsigned ndescs __unused);
enum sidecar_verdict
http_span_middleware(struct unimsg_shm_desc *descs __unused,
		     unsigned ndescs __unused);
enum sidecar_verdict
request_metric_handler(struct unimsg_shm_desc *descs __unused,
		       unsigned ndescs __unused);
enum sidecar_verdict
new_timeout_handler(struct unimsg_shm_desc *descs __unused,
		    unsigned ndescs __unused);
enum sidecar_verdict
forwarded_shim_handler(struct unimsg_shm_desc *descs __unused,
		       unsigned ndescs __unused);
enum sidecar_verdict
proxy_handler(struct unimsg_shm_desc *descs __unused, unsigned ndescs __unused);
/* Tx filters */
enum sidecar_verdict
request_app_metrics_handler(struct unimsg_shm_desc *descs __unused,
			    unsigned ndescs __unused);
enum sidecar_verdict
concurrency_state_handler(struct unimsg_shm_desc *descs __unused,
			  unsigned ndescs __unused);

static filter_t filters[] = {
	NULL,			     /* SIDECAR_FILTER_END */
	request_log_handler,	     /* REQUEST_LOG_HANDLER */
	http_span_middleware,	     /* HTTP_SPAN_MIDDLEWARE */
	request_metric_handler,	     /* REQUEST_METRIC_HANDLER */
	new_timeout_handler,	     /* NEW_TIMEOUT_HANDLER */
	forwarded_shim_handler,	     /* FORWARD_SHIM_HANDLER */
	proxy_handler,		     /* PROXY_HANDLER */
	request_app_metrics_handler, /* REQUEST_APP_METRIC_HANDLER */
	concurrency_state_handler,   /* CONCURRENCY_STATE_HANDLER */
};

int sidecar_init(struct sidecar_shm *shm)
{
	config = &shm->config;
	stats = &shm->stats;
	memset(stats, 0, sizeof(*stats));

	/* TODO: the chain of filters should be set externally */
	config->rx_filetrs_chain[0] = REQUEST_LOG_HANDLER;
	config->rx_filetrs_chain[1] = HTTP_SPAN_MIDDLEWARE;
	config->rx_filetrs_chain[2] = REQUEST_METRIC_HANDLER;
	config->rx_filetrs_chain[3] = NEW_TIMEOUT_HANDLER;
	config->rx_filetrs_chain[4] = FORWARD_SHIM_HANDLER;
	config->rx_filetrs_chain[5] = PROXY_HANDLER;
	config->rx_filetrs_chain[6] = SIDECAR_FILTER_END;
	// config->rx_filetrs_chain[0] = SIDECAR_FILTER_END;

	config->tx_filetrs_chain[0] = REQUEST_APP_METRIC_HANDLER;
	config->tx_filetrs_chain[1] = CONCURRENCY_STATE_HANDLER;
	config->tx_filetrs_chain[2] = SIDECAR_FILTER_END;
	// config->tx_filetrs_chain[0] = SIDECAR_FILTER_END;

	response_time_ewma.alpha = 0.2;
	app_response_time_ewma.alpha = 0.2;

	return 0;
}


enum sidecar_verdict sidecar_tx(struct unimsg_shm_desc *descs, unsigned ndescs)
{
	enum sidecar_verdict verdict = SIDECAR_OK;

	for (int i = 0;
	     i < SIDECAR_MAX_FILTERS && verdict == SIDECAR_OK
	     && config->tx_filetrs_chain[i] != SIDECAR_FILTER_END;
	     i++) {
	       	verdict = filters[config->tx_filetrs_chain[i]](descs, ndescs);
	}

	return verdict;
}

enum sidecar_verdict sidecar_rx(struct unimsg_shm_desc *descs, unsigned ndescs)
{
	enum sidecar_verdict verdict = SIDECAR_OK;

	for (int i = 0;
	     i < SIDECAR_MAX_FILTERS && verdict == SIDECAR_OK
	     && config->rx_filetrs_chain[i] != SIDECAR_FILTER_END;
	     i++) {
	       	verdict = filters[config->rx_filetrs_chain[i]](descs, ndescs);
	}

	return verdict;
}

/* Rx filters */

enum sidecar_verdict
request_log_handler(struct unimsg_shm_desc *descs __unused,
		    unsigned ndescs __unused)
{
	response_time_ewma.ingress_ts = get_time_ms();

	return SIDECAR_OK;
}

enum sidecar_verdict
http_span_middleware(struct unimsg_shm_desc *descs __unused,
		     unsigned ndescs __unused)
{
	/* TODO: implement */

	return SIDECAR_OK;
}

enum sidecar_verdict
request_metric_handler(struct unimsg_shm_desc *descs __unused,
		       unsigned ndescs __unused)
{
	stats->request_count++;

	return SIDECAR_OK;
}

enum sidecar_verdict
new_timeout_handler(struct unimsg_shm_desc *descs __unused,
		    unsigned ndescs __unused)
{
	/* TODO: implement */

	return SIDECAR_OK;
}

enum sidecar_verdict
forwarded_shim_handler(struct unimsg_shm_desc *descs __unused,
		       unsigned ndescs __unused)
{
	/* TODO: implement */

	return SIDECAR_OK;
}

enum sidecar_verdict
proxy_handler(struct unimsg_shm_desc *descs __unused, unsigned ndescs __unused)
{
	app_response_time_ewma.ingress_ts = get_time_ms();

	return SIDECAR_OK;
}

/* Tx filters */

enum sidecar_verdict
request_app_metrics_handler(struct unimsg_shm_desc *descs __unused,
			    unsigned ndescs __unused)
{
	unsigned long time = get_time_ms() - app_response_time_ewma.ingress_ts;
	stats->app_response_time_ms = ewma_update(&app_response_time_ewma,
						  time);

	stats->app_request_count++;

	return SIDECAR_OK;
}

enum sidecar_verdict
concurrency_state_handler(struct unimsg_shm_desc *descs __unused,
			  unsigned ndescs __unused)
{
	unsigned long time = get_time_ms() - response_time_ewma.ingress_ts;
	stats->response_time_ms = ewma_update(&response_time_ewma, time);

	return SIDECAR_OK;
}
