/*
 * Some sort of Copyright
 */

#ifndef __LIBH2OS_API__
#define __LIBH2OS_API__

#include <uk/essentials.h>

#ifdef CONFIG_LIBH2OS_MEMORY_PROTECTION
#include <uk/arch/lcpu.h>
#include <uk/arch/types.h>
#include <uk/preempt.h>

#define MPK_ACCESS_DISABLE 0x1
#define MPK_WRITE_DISABLE  0x2 

/* The default key assigend to pages, any piece of code can access it */
#define H2OS_DEFAULT_KEY 0x0UL
/* This key protects data structures that cannot be modified after h2os has been
 * initialized (only IDT for now). Write is denied outside h2os, read is always
 * allowed
 */
#define H2OS_WRITE_KEY 0x2UL
/* This key protects h2os exclusive data, no access is allowed outside h2os */
#define H2OS_ACCESS_KEY 0x1UL

#define H2OS_PKRU_DEFAULT						\
	((MPK_ACCESS_DISABLE << (2 * H2OS_ACCESS_KEY))			\
	 | (MPK_WRITE_DISABLE << (2 * H2OS_WRITE_KEY)))
#define H2OS_PKRU_PRIVILEGED 0

#define H2OS_STACK_SIZE 4 * 1024
#define H2OS_MAX_STACKS 1

extern char h2os_stacks[H2OS_MAX_STACKS][H2OS_STACK_SIZE]
__attribute__((aligned(8)));

#define H2OS_API_DEFINE(name, ...)					\
	H2OS_API_DEFINEx(UK_NARGS(__VA_ARGS__), name, ##__VA_ARGS__)
#define H2OS_API_DEFINEx(x, name, ...)					\
	UK_CONCAT(H2OS_API_DEFINE, x)(name, ##__VA_ARGS__)


#define GATE_ENTRY							\
	/* Are we already in privileged mode? */			\
	"xor %%r12, %%r12\n\t"						\
	"xor %%rcx, %%rcx\n\t"						\
	"rdpkru\n\t"							\
	"cmp %[pkey], %%rax\n\t"					\
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
		uk_preempt_disable();					\
		int rc = 0;						\
		asm volatile (						\
			GATE_ENTRY					\
			"call _" #name "\n\t"				\
			GATE_EXIT					\
			: [rc]"=&r"(rc)					\
			: [pkey]"i"(H2OS_PKRU_PRIVILEGED),		\
			  [dkey]"i"(H2OS_PKRU_DEFAULT),			\
			  [stack]"r"(&h2os_stacks[0][H2OS_STACK_SIZE])	\
			: "rax", "rdi", "rsi", "rdx", "rcx", "r8", "r9",\
			  "r10", "r11", "r12"				\
		);							\
		uk_preempt_enable();					\
		return rc;						\
	}

#define H2OS_API_DEFINE2(name, type0, arg0) 				\
	int _##name(type0 arg0);					\
	static inline __attribute__((always_inline))			\
	int name(type0 arg0)						\
	{								\
		uk_preempt_disable();					\
		int rc = 0;						\
		register unsigned long _arg0 asm("rdi")			\
			= (unsigned long)arg0;				\
		asm volatile (						\
			GATE_ENTRY					\
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
		uk_preempt_enable();					\
		return rc;						\
	}

#define H2OS_API_DEFINE4(name, type0, arg0, type1, arg1)		\
	int _##name(type0 arg0, type1 arg1);				\
	static inline __attribute__((always_inline))			\
	int name(type0 arg0, type1 arg1)				\
	{								\
		uk_preempt_disable();					\
		int rc = 0;						\
		register unsigned long _arg0 asm("rdi")			\
			= (unsigned long)arg0;				\
		register unsigned long _arg1 asm("rsi")			\
			= (unsigned long)arg1;				\
		asm volatile (						\
			GATE_ENTRY					\
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
		uk_preempt_enable();					\
		return rc;						\
	}

#define H2OS_API_DEFINE6(name, type0, arg0, type1, arg1, type2, arg2)	\
	int _##name(type0 arg0, type1 arg1, type2 arg2);		\
	static inline __attribute__((always_inline))			\
	int name(type0 arg0, type1 arg1, type2 arg2)			\
	{								\
		uk_preempt_disable();					\
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
		uk_preempt_enable();					\
		return rc;						\
	}

#define H2OS_API_DEFINE8(name, type0, arg0, type1, arg1, type2, arg2,	\
			 type3, arg3)					\
	int _##name(type0 arg0, type1 arg1, type2 arg2, type3 arg3);	\
	static inline __attribute__((always_inline))			\
	int name(type0 arg0, type1 arg1, type2 arg2, type3 arg3)	\
	{								\
		uk_preempt_disable();					\
		int rc = 0;						\
		register unsigned long _arg0 asm("rdi")			\
			= (unsigned long)arg0;				\
		register unsigned long _arg1 asm("rsi")			\
			= (unsigned long)arg1;				\
		/* The third and fourth arguments (arg2 and arg3) are */\
		/* located in rdx adn rcx, but we need to clear them  */\
		/* wrpkru, so let gcc choose where to put them and    */\
		/* then mov them				      */\
		unsigned long _arg2 = (unsigned long)arg2;		\
		unsigned long _arg3 = (unsigned long)arg3;		\
		asm volatile (						\
			GATE_ENTRY					\
			"mov %[_arg2], %%rdx\n\t"			\
			"mov %[_arg3], %%rcx\n\t"			\
			"call _" #name "\n\t"				\
			GATE_EXIT					\
			: [rc]"=&r"(rc),				\
			  [_arg0]"+r"(_arg0),				\
			  [_arg1]"+r"(_arg1),				\
			  [_arg2]"+r"(_arg2),				\
			  [_arg3]"+r"(_arg3)				\
			: [pkey]"i"(H2OS_PKRU_PRIVILEGED),		\
			  [dkey]"i"(H2OS_PKRU_DEFAULT),			\
			  [stack]"r"(&h2os_stacks[0][H2OS_STACK_SIZE])	\
			: "rax", "rdx", "rcx", "r8", "r9", "r10", "r11",\
			  "r12"						\
		);							\
		uk_preempt_enable();					\
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