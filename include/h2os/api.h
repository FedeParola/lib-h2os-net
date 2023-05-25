/*
 * Some sort of Copyright
 */

#ifndef __LIBH2OS_API__
#define __LIBH2OS_API__

#include <h2os/memory_protection.h>
#include <uk/essentials.h>

#ifdef CONFIG_LIBH2OS_MEMORY_PROTECTION
extern
char h2os_stacks[H2OS_MAX_STACKS][H2OS_STACK_SIZE] __attribute__((aligned(8)));

#define H2OS_API_DEFINE(name, ...)					\
	H2OS_API_DEFINEx(UK_NARGS(__VA_ARGS__), name, ##__VA_ARGS__)
#define H2OS_API_DEFINEx(x, name, ...)					\
	UK_CONCAT(H2OS_API_DEFINE, x)(name, ##__VA_ARGS__)


#define GATE_ENTRY							\
	/* Are we already in privileged mode? */			\
	"xor %%r12, %%r12\n\t"						\
	"xor %%rcx, %%rcx\n\t"						\
	"rdpkru\n\t"							\
	"cmp $0, %%rax\n\t"						\
	"je 1f\n\t"							\
	"mov $1, %%r12\n\t"						\
	/* Set privileged PKRU */					\
	"xor %%rdx, %%rdx\n\t"						\
	"xor %%rcx, %%rcx\n\t"						\
	"mov %[pkey], %%rax\n\t"					\
	"wrpkru\n\t"							\
	/* Switch stack */						\
	"mov %%rsp, -0x8(%[stack])\n\t"					\
	"mov %[stack], %%rsp\n\t"					\
	"sub $0x8, %%rsp\n\t"						\
	"1:"

#define GATE_EXIT							\
	/* Save call return code */					\
	"mov %%eax, %[rc]\n\t"						\
	/* Were we already in privileged mode? */			\
	"cmp $0, %%r12\n\t"						\
	"je 2f\n\t"							\
	/* Reset stack */						\
	"mov -0x8(%[stack]), %%rsp\n\t"					\
	/* Set default PKRU */						\
	"xor %%rdx, %%rdx\n\t"						\
	"xor %%rcx, %%rcx\n\t"						\
	"mov %[dkey], %%rax\n\t"					\
	"wrpkru\n\t"							\
	"cmp %[dkey], %%rax\n\t"					\
	"je 2f\n\t"							\
	"int $0xd\n\t" /* ROP detected, crash */			\
	"2:\n\t"

#define H2OS_API_DEFINE0(name) 						\
	int _##name();							\
	static inline __attribute__((always_inline))			\
	int name()							\
	{								\
		int rc = 0;						\
		asm volatile (						\
			GATE_ENTRY					\
			/* Call h2os function */			\
			"call _" #name "\n\t"				\
			GATE_EXIT					\
			: [rc]"=&r"(rc)					\
			: [pkey]"i"(H2OS_PKRU_PRIVILEGED),		\
			  [dkey]"i"(H2OS_PKRU_DEFAULT),			\
			  [stack]"r"(&h2os_stacks[0][H2OS_STACK_SIZE])	\
			: "rax", "rdi", "rsi", "rdx", "rcx", "r8", "r9",\
			  "r10", "r11", "r12"				\
		);							\
		return rc;						\
	}

#define H2OS_API_DEFINE2(name, type0, arg0) 				\
	int _##name(type0 arg0);					\
	static inline __attribute__((always_inline))			\
	int name(type0 arg0)						\
	{								\
		int rc = 0;						\
		register unsigned long _arg0 asm("rdi")			\
			= (unsigned long)arg0;				\
		asm volatile (						\
			GATE_ENTRY					\
			/* Call h2os function */			\
			"call _" #name "\n\t"				\
			GATE_EXIT					\
			: [rc]"=&r"(rc),				\
			  [_arg0]"+r"(_arg0)				\
			: [pkey]"i"(H2OS_PKRU_PRIVILEGED),		\
			  [dkey]"i"(H2OS_PKRU_DEFAULT),			\
			  [stack]"r"(&h2os_stacks[0][H2OS_STACK_SIZE])	\
			: "rax", "rsi", "rdx", "rcx", "r8", "r9", "r10",\
			  "r11", "r12"					\
		);							\
		return rc;						\
	}

#define H2OS_API_DEFINE4(name, type0, arg0, type1, arg1)		\
	int _##name(type0 arg0, type1 arg1);				\
	static inline __attribute__((always_inline))			\
	int name(type0 arg0, type1 arg1)				\
	{								\
		int rc = 0;						\
		register unsigned long _arg0 asm("rdi")			\
			= (unsigned long)arg0;				\
		register unsigned long _arg1 asm("rsi")			\
			= (unsigned long)arg1;				\
		asm volatile (						\
			GATE_ENTRY					\
			/* Call h2os function */			\
			"call _" #name "\n\t"				\
			GATE_EXIT					\
			: [rc]"=&r"(rc),				\
			  [_arg0]"+r"(_arg0),				\
			  [_arg1]"+r"(_arg1)				\
			: [pkey]"i"(H2OS_PKRU_PRIVILEGED),		\
			  [dkey]"i"(H2OS_PKRU_DEFAULT),			\
			  [stack]"r"(&h2os_stacks[0][H2OS_STACK_SIZE])	\
			: "rax", "rdx", "rcx", "r8", "r9", "r10", "r11",\
			  "r12"						\
		);							\
		return rc;						\
	}

#define H2OS_API_DEFINE6(name, type0, arg0, type1, arg1, type2, arg2)	\
	int _##name(type0 arg0, type1 arg1, type2 arg2);		\
	static inline __attribute__((always_inline))			\
	int name(type0 arg0, type1 arg1, type2 arg2)			\
	{								\
		int rc = 0;						\
		register unsigned long _arg0 asm("rdi")			\
			= (unsigned long)arg0;				\
		register unsigned long _arg1 asm("rsi")			\
			= (unsigned long)arg1;				\
		/* The third argument (arg2) is located in rdx, but  */	\
		/* we need to clear it for wrpkru, so let gcc choose */ \
		/* where to put it and then mov it		     */ \
		unsigned long _arg2 = (unsigned long)arg2;		\
		asm volatile (						\
			GATE_ENTRY					\
			/* Call h2os function */			\
			"mov %[_arg2], %%rdx\n\t"			\
			"call _" #name "\n\t"				\
			GATE_EXIT					\
			: [rc]"=&r"(rc),				\
			  [_arg0]"+r"(_arg0),				\
			  [_arg1]"+r"(_arg1),				\
			  [_arg2]"+r"(_arg2)				\
			: [pkey]"i"(H2OS_PKRU_PRIVILEGED),		\
			  [dkey]"i"(H2OS_PKRU_DEFAULT),			\
			  [stack]"r"(&h2os_stacks[0][H2OS_STACK_SIZE])	\
			: "rax", "rdx", "rcx", "r8", "r9", "r10", "r11",\
			  "r12"						\
		);							\
		return rc;						\
	}

#else /* !CONFIG_LIBH2OS_MEMORY_PROTECTION */
#define ARG_VAL(type, arg) arg
#define ARG_DECL(type, arg) type arg

#define ARG_MAP0(...)
#define ARG_MAP2(m, type, arg) m(type, arg)
#define ARG_MAP4(m, type, arg, ...) m(type, arg), ARG_MAP2(m, __VA_ARGS__)
#define ARG_MAP6(m, type, arg, ...) m(type, arg), ARG_MAP4(m, __VA_ARGS__)
#define ARG_MAPx(nr_args, ...) UK_CONCAT(ARG_MAP, nr_args)(__VA_ARGS__)

#define H2OS_API_DEFINE(name, ...)					\
	_H2OS_API_DEFINE(UK_NARGS(__VA_ARGS__), name, ##__VA_ARGS__)
#define _H2OS_API_DEFINE(x, name, ...)					\
	int _##name(ARG_MAPx(x, ARG_DECL, ##__VA_ARGS__));		\
	static inline __attribute__((always_inline))			\
	int name(ARG_MAPx(x, ARG_DECL, ##__VA_ARGS__))			\
	{								\
		return _##name(ARG_MAPx(x, ARG_VAL, ##__VA_ARGS__));	\
	}

#endif /* CONFIG_LIBH2OS_MEMORY_PROTECTION */

#endif /* __LIBH2OS_API__ */