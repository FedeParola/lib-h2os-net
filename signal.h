/*
 * Some sort of Copyright
 */

#ifndef __LIBH2OS_SIGNAL__
#define __LIBH2OS_SIGNAL__

#include "signal_queue.h"

int signal_send(unsigned vm_id, struct signal *signal);

#endif /* __LIBH2OS_SIGNAL__ */