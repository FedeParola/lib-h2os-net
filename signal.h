/*
 * Some sort of Copyright
 */

#ifndef __LIBH2OS_SIGNAL__
#define __LIBH2OS_SIGNAL__

struct signal {
	unsigned long target_thread;
};

int signal_send(unsigned vm_id, struct signal *signal);

#endif /* __LIBH2OS_SIGNAL__ */