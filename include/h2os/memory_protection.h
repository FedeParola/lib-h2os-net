/*
 * Some sort of Copyright
 */

#ifndef __LIBH2OS_MEMORY_PROTECTION__
#define __LIBH2OS_MEMORY_PROTECTION__

// #ifdef CONFIG_LIBH2OS_MEMORY_PROTECTION
#include <uk/arch/types.h>

#define MPK_ACCESS_DISABLE 0x1
#define MPK_WRITE_DISABLE  0x2 
#define MPK_PKRU_VAL(key, perm) ({ perm << (2 * key); })

/* The default key assigend to pages, any piece of code can access it */
#define H2OS_DEFAULT_KEY 0x0UL
/* This key protects data structures that cannot be modified after h2os has been
 * initialized (IDT and page tables). Write is denied outside h2os, read is
 * always allowed
 */
#define H2OS_WRITE_KEY 0x2UL
/* This key protects h2os exclusive data, no access is allowed outside h2os */
#define H2OS_ACCESS_KEY 0x1UL

#define H2OS_PKRU_DEFAULT						\
	(MPK_PKRU_VAL(H2OS_ACCESS_KEY, MPK_ACCESS_DISABLE)		\
	| MPK_PKRU_VAL(H2OS_WRITE_KEY, MPK_WRITE_DISABLE))
#define H2OS_PKRU_PRIVILEGED 0

#define H2OS_STACK_SIZE 4 * 1024
#define H2OS_MAX_STACKS 1

int h2os_check_frame_protected(__paddr_t addr);

static inline void h2os_set_privilege()
{
	__builtin_ia32_wrpkru(0);
}

static inline void h2os_reset_privilege()
{
	__builtin_ia32_wrpkru(
		MPK_PKRU_VAL(H2OS_ACCESS_KEY, MPK_ACCESS_DISABLE)
		| MPK_PKRU_VAL(H2OS_WRITE_KEY, MPK_WRITE_DISABLE));
}

// #else /* !CONFIG_LIBH2OS_MEMORY_PROTECTION */
// static inline void h2os_enter() {}
// static inline void h2os_exit() {}
// #endif /* CONFIG_LIBH2OS_MEMORY_PROTECTION */

#endif /* __LIBH2OS_MEMORY_PROTECTION__ */