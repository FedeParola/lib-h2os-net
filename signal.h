/*
 * Some sort of Copyright
 */

#ifndef __LIBUNIMSG_SIGNAL__
#define __LIBUNIMSG_SIGNAL__

struct signal {
	unsigned long target_thread;
};

int signal_send(unsigned vm_id, struct signal *signal);

#endif /* __LIBUNIMSG_SIGNAL__ */