/*
 * Some sort of Copyright
 */

#include <string.h>
#include <uk/plat/qemu/ivshmem.h>
#include <uk/sched.h>
#include "common.h"
#include "signal.h"

#define POLL_BUDGET 32

static struct uk_thread *signal_poll_thread;
static struct signal_queue *signal_queues;
static struct signal_queue *local_queue;

static __noreturn void signal_poll(void *arg __unused)
{
	struct signal signal;

again:
	for (int i = 0; i < POLL_BUDGET; i++) {
		if (signal_queue_consume(local_queue, &signal)) {
			/* The queue is empty, check again with interrupts
			 * disabled, so we don't miss an interrupt. This only
			 * works if thread and irq handler run on the same vCPU.
			 */
			unsigned long flags = ukplat_lcpu_save_irqf();
			/* TODO: move uk_thread_block() here if we don't set the
			 * affinity of this thread
			 */
			if (signal_queue_consume(local_queue, &signal)) {
				uk_thread_block(uk_thread_current());
				ukplat_lcpu_restore_irqf(flags);
				break;
			}

			/* Something appeared on the queue, keep polling */
			ukplat_lcpu_restore_irqf(flags);
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

static int handle_irq(void *arg __unused)
{
	/* One idea to reduce latency could be performing a first poll round
	 * direclty in the irq handler, however this could interleave with the
	 * poll thread, making the queue multi-consumer. This doesn't apply if
	 * we guarantee that the irq handler is never executed if the poll
	 * thread is running, but I can't think of a way
	 */
	uk_thread_wake(signal_poll_thread);

	return 1;
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
	local_queue = &signal_queues[ivshmem.doorbell_id];

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
	int was_empty;
	while (signal_queue_produce(&signal_queues[vm_id], signal, &was_empty));
	if (was_empty)
		qemu_ivshmem_interrupt_peer(CONTROL_IVSHMEM_ID, vm_id, 0);

	return 0;
}