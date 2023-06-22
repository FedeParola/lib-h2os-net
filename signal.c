/*
 * Some sort of Copyright
 */

#include <h2os/api.h>
#include <string.h>
#include <uk/plat/qemu/ivshmem.h>
#include <uk/sched.h>
#include "common.h"
#include "ring.h"
#include "signal.h"

#define POLL_BUDGET 32

struct signal_queue {
	int need_wakeup;
	struct h2os_ring r;
};

#ifdef CONFIG_LIBH2OS_MEMORY_PROTECTION
/* The signal_poll_thread pointer is accessed by the irq handler in unprivileged
 * mode, so it can't be protected. This isn't a security problem, if the pointer
 * is replace some unprivileged thread will be woken.
 */
__section(".bss_unprotected")
#endif
static struct uk_thread *signal_poll_thread;
static struct signal_queue *signal_queues;
static struct signal_queue *local_queue;

H2OS_API_DEFINE(do_signal_poll)
__noreturn int _do_signal_poll()
{
	struct signal signal;

again:
	for (int i = 0; i < POLL_BUDGET; i++) {
		if (h2os_ring_dequeue(&local_queue->r, &signal, 1)) {
			uk_thread_block(uk_thread_current());
			__atomic_store_n(&local_queue->need_wakeup, 1,
					 __ATOMIC_SEQ_CST /*__ATOMIC_RELEASE*/);
			if (h2os_ring_dequeue(&local_queue->r, &signal, 1))
				break;

			/* Something appeared on the queue, keep polling */
			__atomic_store_n(&local_queue->need_wakeup, 0,
					 __ATOMIC_SEQ_CST /*__ATOMIC_RELEASE*/);
			uk_thread_wake(uk_thread_current());
		}

		/* Here we trust the content of the signal */
		uk_thread_wake((struct uk_thread *)signal.target_thread);
	}
	
	/* This yield is only needed with the cooperative scheduler I think. It
	 * can be moved after the thread_block with the preemptive scheduler
	 */
	uk_sched_yield();

	goto again;
}

static __noreturn void signal_poll(void *arg __unused)
{
	/* The thread starts as unprivileged code, call privileged function
	 * through gate that never returns
	 */
	while (1)
		do_signal_poll();
}

static int handle_irq(void *arg __unused)
{
	/* One idea to reduce latency could be performing a first poll round
	 * directly in the irq handler, however this could interleave with the
	 * poll thread, making the queue multi-consumer. This doesn't apply if
	 * we guarantee that the irq handler is never executed if the poll
	 * thread is running, but I can't think of a way
	 */
	uk_thread_wake(signal_poll_thread);

	return 1;
}

static struct signal_queue *get_queue(unsigned vm_id)
{
	/* All rings have the same size so we use the size of the first one */
	return (void *)signal_queues
		+ (sizeof(struct signal_queue)
		   + h2os_ring_objs_memsize(&signal_queues[0].r)) * vm_id;
}

int signal_init(struct qemu_ivshmem_info ivshmem)
{
	int rc;

	signal_poll_thread = uk_sched_thread_create(uk_sched_current(),
						    signal_poll, NULL,
						    "h2os_signal_poll");
	if (!signal_poll_thread) {
		uk_pr_err("Error creating signal poll thread\n");
		return -ENOMEM;
	}

	/* TODO: Need to set the thread affinity to the same vCPU of the irq
	 * handler, to avoid missing an irq
	 */

	struct h2os_shm_header *shmh = ivshmem.addr;
	signal_queues = (void *)shmh + shmh->signal_off;
	local_queue = get_queue(ivshmem.doorbell_id);

	rc = qemu_ivshmem_set_interrupt_handler(CONTROL_IVSHMEM_ID, 0,
						handle_irq, NULL);
	if (rc) {
		uk_pr_err("Error registering interrupt handler: %s\n",
			  strerror(-rc));
		return rc;
	}

	return 0;
}

int signal_send(unsigned vm_id, struct signal *signal)
{
	UK_ASSERT(vm_id < H2OS_MAX_VMS);

	/* Busy-loop on a full queue for now */
	/* TODO: how to handle this? I'm afraid backpressure here could cause a
	 * deadlock
	 */
	struct signal_queue *q = get_queue(vm_id);
	while (h2os_ring_enqueue(&q->r, signal, 1));

	int need_wakeup = __atomic_load_n(&q->need_wakeup, __ATOMIC_SEQ_CST /*__ATOMIC_ACQUIRE*/);
	if (need_wakeup &&
	    __atomic_compare_exchange_n(&q->need_wakeup, &need_wakeup, 0, 0,
					__ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
		qemu_ivshmem_interrupt_peer(CONTROL_IVSHMEM_ID, vm_id, 0);

	return 0;
}