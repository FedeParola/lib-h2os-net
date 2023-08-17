/*
 * Some sort of Copyright
 */

#ifndef __LIBUNIMSG_API__
#define __LIBUNIMSG_API__

#include <uk/essentials.h>

#ifdef CONFIG_LIBUNIMSG_MEMORY_PROTECTION
#include <uk/arch/lcpu.h>
#include <uk/arch/types.h>
#include <uk/preempt.h>
#include <uk/thread.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MPK_ACCESS_DISABLE 0x1
#define MPK_WRITE_DISABLE  0x2 

/* The default key assigend to pages, any piece of code can access it */
#define UNIMSG_DEFAULT_KEY 0x0UL
/* This key protects data structures that cannot be modified after unimsg has
 * been initialized (only IDT for now). Write is denied outside unimsg, read is
 * always allowed
 */
#define UNIMSG_WRITE_KEY 0x2UL
/* This key protects unimsg exclusive data, no access is allowed outside
 * unimsg
 */
#define UNIMSG_ACCESS_KEY 0x1UL

#define UNIMSG_PKRU_DEFAULT						\
	((MPK_ACCESS_DISABLE << (2 * UNIMSG_ACCESS_KEY))		\
	 | (MPK_WRITE_DISABLE << (2 * UNIMSG_WRITE_KEY)))
#define UNIMSG_PKRU_PRIVILEGED 0

struct thread_info {
	unsigned long used;
	void *protected_stack;
	struct ukarch_ctx ctx;
	struct ukarch_ectx *ectx;
	struct thread_info *freelist_next;
} __align(64);
/* Alignment simplifies indexing the thread_infos array in assembly gates */

extern struct thread_info thread_infos[CONFIG_LIBUNIMSG_MAX_THREADS];

#define UNIMSG_API_DEFINE(name, ...)					\
	UNIMSG_API_DEFINEx(UK_NARGS(__VA_ARGS__), name, ##__VA_ARGS__)
#define UNIMSG_API_DEFINEx(x, name, ...)				\
	UK_CONCAT(UNIMSG_API_DEFINE, x)(name, ##__VA_ARGS__)

#define GATE_ENTRY							\
	uk_preempt_disable();						\
	int rc = 0;							\
	/* Retrieve the unimsg id of the current thread. If there is  */\
	/* no current thread, it means that the threading system has  */\
	/* not been initialized yet, as well as unimsg.		      */\
	/* This will be a simple function call			      */\
	unsigned long tid = CONFIG_LIBUNIMSG_MAX_THREADS;		\
	struct uk_thread *_t = uk_thread_current();			\
	if (_t)								\
		tid = _t->unimsg_id;					\

#define GATE_EXIT							\
	uk_preempt_enable();						\
	return rc;

#define ASM_OUTPUTS							\
	[rc]"=&r"(rc),							\
	[tid]"+r"(tid)

#define ASM_INPUTS							\
	[pkey]"i"(UNIMSG_PKRU_PRIVILEGED),				\
	[dkey]"i"(UNIMSG_PKRU_DEFAULT),					\
	[maxtid]"i"(CONFIG_LIBUNIMSG_MAX_THREADS),			\
	[tinfo]"m"(thread_infos)

#define ASM_ENTRY							\
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
	/* Is the thread id valid? */					\
	"cmp %[maxtid], %[tid]\n\t"					\
	"jge 2f\n\t"							\
	"shl $6, %[tid]\n\t"						\
	"lea %[tinfo], %%rax\n\t"					\
	"cmpq $0, (%%rax, %[tid])\n\t"					\
	"je 2f\n\t"							\
	"mov 0x8(%%rax, %[tid]), %%rdx\n\t"				\
	"mov %%rsp, -0x8(%%rdx)\n\t"					\
	"mov %%rdx, %%rsp\n\t"						\
	"sub $0x8, %%rsp\n\t"						\
"1:\n\t"

#define ASM_EXIT							\
	/* Save call return code */					\
	"mov %%eax, %[rc]\n\t"						\
	/* Were we already in privileged mode? */			\
	"cmp $0, %%r12\n\t"						\
	"je 3f\n\t"							\
	/* Reset stack */						\
	"mov (%%rsp), %%rsp\n\t"					\
	/* Set default PKRU */						\
	"xor %%rdx, %%rdx\n\t"						\
	"xor %%rcx, %%rcx\n\t"						\
	"mov %[dkey], %%rax\n\t"					\
	"wrpkru\n\t"							\
	"cmp %[dkey], %%rax\n\t"					\
	"je 3f\n\t"							\
"2:\n\t"								\
	"int $0xd\n\t" /* ROP detected, crash */			\
"3:\n\t"

#define UNIMSG_API_DEFINE0(name) 					\
	int _##name();							\
	static inline __attribute__((always_inline))			\
	int name()							\
	{								\
		GATE_ENTRY						\
		asm volatile (						\
			ASM_ENTRY					\
			"call _" #name "\n\t"				\
			ASM_EXIT					\
			: ASM_OUTPUTS					\
			: ASM_INPUTS					\
			: "rax", "rdi", "rsi", "rdx", "rcx", "r8", "r9",\
			  "r10", "r11", "r12"				\
		);							\
		GATE_EXIT						\
	}

#define UNIMSG_API_DEFINE2(name, type0, arg0) 				\
	int _##name(type0 arg0);					\
	static inline __attribute__((always_inline))			\
	int name(type0 arg0)						\
	{								\
		GATE_ENTRY						\
		register unsigned long _arg0 asm("rdi")			\
			= (unsigned long)arg0;				\
		asm volatile (						\
			ASM_ENTRY					\
			"call _" #name "\n\t"				\
			ASM_EXIT					\
			: ASM_OUTPUTS,					\
			  [_arg0]"+r"(_arg0)				\
			: ASM_INPUTS					\
			: "rax", "rsi", "rdx", "rcx", "r8", "r9", "r10",\
			  "r11", "r12"					\
		);							\
		GATE_EXIT						\
	}

#define UNIMSG_API_DEFINE4(name, type0, arg0, type1, arg1)		\
	int _##name(type0 arg0, type1 arg1);				\
	static inline __attribute__((always_inline))			\
	int name(type0 arg0, type1 arg1)				\
	{								\
		GATE_ENTRY						\
		register unsigned long _arg0 asm("rdi")			\
			= (unsigned long)arg0;				\
		register unsigned long _arg1 asm("rsi")			\
			= (unsigned long)arg1;				\
		asm volatile (						\
			ASM_ENTRY					\
			"call _" #name "\n\t"				\
			ASM_EXIT					\
			: ASM_OUTPUTS,					\
			  [_arg0]"+r"(_arg0),				\
			  [_arg1]"+r"(_arg1)				\
			: ASM_INPUTS					\
			: "rax", "rdx", "rcx", "r8", "r9", "r10", "r11",\
			  "r12"						\
		);							\
		GATE_EXIT						\
	}

#define UNIMSG_API_DEFINE6(name, type0, arg0, type1, arg1, type2, arg2)	\
	int _##name(type0 arg0, type1 arg1, type2 arg2);		\
	static inline __attribute__((always_inline))			\
	int name(type0 arg0, type1 arg1, type2 arg2)			\
	{								\
		GATE_ENTRY						\
		register unsigned long _arg0 asm("rdi")			\
			= (unsigned long)arg0;				\
		register unsigned long _arg1 asm("rsi")			\
			= (unsigned long)arg1;				\
		/* rdx (arg2) is cleared for wrpkru. Mov the arg later*/\
		unsigned long _arg2 = (unsigned long)arg2;		\
		asm volatile (						\
			ASM_ENTRY					\
			"mov %[_arg2], %%rdx\n\t"			\
			"call _" #name "\n\t"				\
			ASM_EXIT					\
			: ASM_OUTPUTS,					\
			  [_arg0]"+r"(_arg0),				\
			  [_arg1]"+r"(_arg1),				\
			  [_arg2]"+r"(_arg2)				\
			: ASM_INPUTS					\
			: "rax", "rdx", "rcx", "r8", "r9", "r10", "r11",\
			  "r12"						\
		);							\
		GATE_EXIT						\
	}

#define UNIMSG_API_DEFINE8(name, type0, arg0, type1, arg1, type2, arg2,	\
			 type3, arg3)					\
	int _##name(type0 arg0, type1 arg1, type2 arg2, type3 arg3);	\
	static inline __attribute__((always_inline))			\
	int name(type0 arg0, type1 arg1, type2 arg2, type3 arg3)	\
	{								\
		GATE_ENTRY						\
		register unsigned long _arg0 asm("rdi")			\
			= (unsigned long)arg0;				\
		register unsigned long _arg1 asm("rsi")			\
			= (unsigned long)arg1;				\
		/* rdx and rcx (arg2 and arg3) are cleared for wrpkru.*/\
		/* Mov args later			      	      */\
		unsigned long _arg2 = (unsigned long)arg2;		\
		unsigned long _arg3 = (unsigned long)arg3;		\
		asm volatile (						\
			ASM_ENTRY					\
			"mov %[_arg2], %%rdx\n\t"			\
			"mov %[_arg3], %%rcx\n\t"			\
			"call _" #name "\n\t"				\
			ASM_EXIT					\
			: ASM_OUTPUTS,					\
			  [_arg0]"+r"(_arg0),				\
			  [_arg1]"+r"(_arg1),				\
			  [_arg2]"+r"(_arg2),				\
			  [_arg3]"+r"(_arg3)				\
			: ASM_INPUTS					\
			: "rax", "rdx", "rcx", "r8", "r9", "r10", "r11",\
			  "r12"						\
		);							\
		GATE_EXIT						\
	}

#else /* !CONFIG_LIBUNIMSG_MEMORY_PROTECTION */
#ifdef __cplusplus
extern "C" {
#endif

#define ARG_VAL(type, arg) arg
#define ARG_DECL(type, arg) type arg

#define ARG_MAP0(...)
#define ARG_MAP2(m, type, arg) m(type, arg)
#define ARG_MAP4(m, type, arg, ...) m(type, arg), ARG_MAP2(m, __VA_ARGS__)
#define ARG_MAP6(m, type, arg, ...) m(type, arg), ARG_MAP4(m, __VA_ARGS__)
#define ARG_MAP8(m, type, arg, ...) m(type, arg), ARG_MAP6(m, __VA_ARGS__)
#define ARG_MAPx(nr_args, ...) UK_CONCAT(ARG_MAP, nr_args)(__VA_ARGS__)

#define UNIMSG_API_DEFINE(name, ...)					\
	_UNIMSG_API_DEFINE(UK_NARGS(__VA_ARGS__), name, ##__VA_ARGS__)
#define _UNIMSG_API_DEFINE(x, name, ...)				\
	int _##name(ARG_MAPx(x, ARG_DECL, ##__VA_ARGS__));		\
	static inline __attribute__((always_inline))			\
	int name(ARG_MAPx(x, ARG_DECL, ##__VA_ARGS__))			\
	{								\
		return _##name(ARG_MAPx(x, ARG_VAL, ##__VA_ARGS__));	\
	}

#endif /* CONFIG_LIBUNIMSG_MEMORY_PROTECTION */

#ifdef __cplusplus
}
#endif

#endif /* __LIBUNIMSG_API__ */