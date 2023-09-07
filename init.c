/*
 * Some sort of Copyright
 */

#include <errno.h>
#include <string.h>
#include <uk/init.h>
#include <uk/plat/qemu/ivshmem.h>
#include <uk/print.h>
#include "common.h"

int signal_init(struct qemu_ivshmem_info ivshmem);
int net_init(struct qemu_ivshmem_info constrol_ivshmem,
	     struct qemu_ivshmem_info sidecar_ivshmem);
int shm_init(struct qemu_ivshmem_info control_ivshmem,
	     struct qemu_ivshmem_info buffers_ivshmem);

struct uk_alloc *unimsg_allocator;

#ifdef CONFIG_LIBUNIMSG_MEMORY_PROTECTION
#include <unimsg/api.h>
#include <uk/mutex.h>
#include <uk/plat/lcpu.h>
#include <uk/plat/paging.h>
#include <uk/thread.h>

#if CONFIG_LIBUNIMSG_STACK_SIZE * CONFIG_LIBUNIMSG_MAX_THREADS > \
    CONFIG_LIBUNIMSG_HEAP_PAGES * 4096
#error Unimsg heap can`t store all possible stacks
#endif

/* The following code is copied from plat/common/include/x86/paging.h */
#define DIRECTMAP_AREA_START	0xffffff8000000000 /* -512 GiB */
#define DIRECTMAP_AREA_END	0xffffffffffffffff
#define DIRECTMAP_AREA_SIZE	(DIRECTMAP_AREA_END - DIRECTMAP_AREA_START + 1)

static inline __vaddr_t
x86_directmap_paddr_to_vaddr(__paddr_t paddr)
{
	UK_ASSERT(paddr < DIRECTMAP_AREA_SIZE);
	return (__vaddr_t)paddr + DIRECTMAP_AREA_START;
}

/* The following part is copied from boot.c to get the proper allocator */
/* FIXME: allocators are hard-coded for now */
#if CONFIG_LIBUKBOOT_INITBBUDDY
#include <uk/allocbbuddy.h>
#define uk_alloc_init uk_allocbbuddy_init
#elif CONFIG_LIBUKBOOT_INITREGION
#include <uk/allocregion.h>
#define uk_alloc_init uk_allocregion_init
#elif CONFIG_LIBUKBOOT_INITMIMALLOC
#include <uk/mimalloc.h>
#define uk_alloc_init uk_mimalloc_init
#elif CONFIG_LIBUKBOOT_INITTLSF
#include <uk/tlsf.h>
#define uk_alloc_init uk_tlsf_init
#elif CONFIG_LIBUKBOOT_INITTINYALLOC
#include <uk/tinyalloc.h>
#define uk_alloc_init uk_tinyalloc_init
#endif

#define UNIMSG_MAX_BLACKLIST_SIZE 2048

/* Information on the task that was interrupted. If the task was running
 * privileged code, no change of the return rip and rsp are allowed (i.e., no
 * preeption).
 */
/* TODO: should we align it to cache line to avoid cache bouncing */
struct irq_return_info {
	unsigned long rip;
	unsigned long rsp;
	char privileged;
};

__section(".interrupt_unimsg")
struct irq_return_info unimsg_irq_ret_info[CONFIG_UKPLAT_LCPU_MAXCOUNT];

struct frame_range {
	__paddr_t start;
	__paddr_t end; /* First frame after the range */
};

static struct frame_range frame_blacklist[UNIMSG_MAX_BLACKLIST_SIZE];
static unsigned blacklist_size = 0;

extern char _text_unimsg_start[], _text_unimsg_end[];
extern char _rodata_unimsg_start[], _rodata_unimsg_end[];
extern char _data_unimsg_start[], _data_unimsg_end[];
extern char _bss_unimsg_start[], _bss_unimsg_end[];
extern char _interrupt_unimsg_start[], _interrupt_unimsg_end[];

struct thread_to_register {
	struct thread_to_register *next;
	struct uk_thread *t;
};

struct thread_info thread_infos[CONFIG_LIBUNIMSG_MAX_THREADS];
static struct thread_info *thread_info_freelist;
static struct uk_mutex thread_info_freelist_mtx;
struct thread_to_register *threads_to_register;
static int initialized = 0;

int _unimsg_thread_register(struct uk_thread *t)
{
	if (!initialized) {
		struct thread_to_register *tr =
				uk_malloc(uk_alloc_get_default(),
					  sizeof(struct thread_to_register));
		if (!tr)
			return -ENOMEM;
		tr->t = t;
		tr->next = threads_to_register;
		threads_to_register = tr;

		return 0;
	}

	uk_mutex_lock(&thread_info_freelist_mtx);
	if (thread_info_freelist == NULL) {
		uk_mutex_unlock(&thread_info_freelist_mtx);
		return -ENOMEM;
	}
	struct thread_info *ti = thread_info_freelist;
	thread_info_freelist = ti->freelist_next;
	uk_mutex_unlock(&thread_info_freelist_mtx);

	ti->ctx = t->ctx;
	ti->ectx = uk_memalign(unimsg_allocator, ukarch_ectx_align(),
			       ukarch_ectx_size());
	if (!ti->ectx) {
		uk_mutex_lock(&thread_info_freelist_mtx);
		ti->freelist_next = thread_info_freelist;
		thread_info_freelist = ti;
		uk_mutex_unlock(&thread_info_freelist_mtx);
		return -ENOMEM;
	}
	memcpy(ti->ectx, t->ectx, ukarch_ectx_size());
	/* Set the PKRU part of ectx with UNIMSG_PKRU_DEFAULT to guarantee that
	 * all threads start in unprivileged mode
	 */
	unsigned eax, ebx, ecx, edx;
	ukarch_x86_cpuid(0xd, 0x9, &eax, &ebx, &ecx, &edx);
	*(unsigned long *)((void *)ti->ectx + ebx) = UNIMSG_PKRU_DEFAULT;

	ti->protected_stack = uk_memalign(unimsg_allocator, 8,
					  CONFIG_LIBUNIMSG_STACK_SIZE);
	if (!ti->protected_stack) {
		uk_free(unimsg_allocator, ti->ectx);
		uk_mutex_lock(&thread_info_freelist_mtx);
		ti->freelist_next = thread_info_freelist;
		thread_info_freelist = ti;
		uk_mutex_unlock(&thread_info_freelist_mtx);
		return -ENOMEM;
	}
	ti->protected_stack += CONFIG_LIBUNIMSG_STACK_SIZE;

	ti->used = 1;
	t->unimsg_id = ti - thread_infos;

	uk_pr_info("Registered thread %p (%s)\n", t,
		   t->name ? t->name : "unnamed");

	return 0;
}

int _unimsg_thread_release(struct uk_thread *t)
{
	unsigned long id = t->unimsg_id;
	if (id >= CONFIG_LIBUNIMSG_MAX_THREADS)
		return -EINVAL;
	struct thread_info *ti = &thread_infos[id];

	uk_mutex_lock(&thread_info_freelist_mtx);
	if (!ti->used) {
		uk_mutex_unlock(&thread_info_freelist_mtx);
		return -EINVAL;
	}
	ti->used = 0;
	uk_free(unimsg_allocator, ti->ectx);
	uk_free(unimsg_allocator,
		ti->protected_stack - CONFIG_LIBUNIMSG_STACK_SIZE);
	ti->freelist_next = thread_info_freelist;
	thread_info_freelist = ti;
	uk_mutex_unlock(&thread_info_freelist_mtx);

	return 0;
}

int _uk_sched_thread_switch(struct uk_thread * next)
{
	struct uk_thread *prev;

	prev = ukplat_per_lcpu_current(__uk_sched_thread_current);

	UK_ASSERT(prev);

	ukplat_per_lcpu_current(__uk_sched_thread_current) = next;

	unsigned long next_id = next->unimsg_id, prev_id = prev->unimsg_id;
	if (next_id >= CONFIG_LIBUNIMSG_MAX_THREADS
	    || prev_id >= CONFIG_LIBUNIMSG_MAX_THREADS)
		UK_CRASH("Invalid thread id");

	struct thread_info *next_info = &thread_infos[next_id];
	struct thread_info *prev_info = &thread_infos[prev_id];
	if (!next_info->used || !prev_info->used)
		UK_CRASH("Invalid thread id");

	prev->tlsp = ukplat_tlsp_get();
	ukarch_ectx_store(prev_info->ectx);

	/* Load next TLS and extended registers before context switch.
	 * This avoids requiring special initialization code for newly
	 * created threads to do the loading.
	 */
	ukplat_tlsp_set(next->tlsp);

	ukarch_ctx_switch(&prev_info->ctx, &next_info->ctx, next_info->ectx);

	return 0;
}

int _ukarch_pte_read(__vaddr_t pt_vaddr, unsigned int lvl, unsigned int idx,
		     __pte_t *pte)
{
	(void)lvl;

#ifdef CONFIG_LIBUKDEBUG
	UK_ASSERT(idx < PT_Lx_PTES(lvl));
#endif /* CONFIG_LIBUKDEBUG */

	*pte = *((__pte_t *)pt_vaddr + idx);

	return 0;
}

int _ukarch_pte_write(__vaddr_t pt_vaddr, unsigned int lvl, unsigned int idx,
		      __pte_t pte)
{
	(void)lvl;

#ifdef CONFIG_LIBUKDEBUG
	UK_ASSERT(idx < PT_Lx_PTES(lvl));
#endif /* CONFIG_LIBUKDEBUG */

	/* TODO: for PKUs to work al PTEs in the hierarchy that leads to the
	 * page resolution must be tagged as user pages. At the moment I'm
	 * tagging all pages of the unikernel as user to simplify things. Is
	 * there a more granular way to do so?
	 */
	pte |= X86_PTE_US;

	/* Crash if the modified pte references a blacklisted frame */
	__paddr_t paddr = PT_Lx_PTE_PADDR(pte, lvl);
	for (unsigned i = 0; i < blacklist_size; i++)
		if (paddr >= frame_blacklist[i].start
		    && paddr < frame_blacklist[i].end)
			UK_CRASH("Illegal page table update detected\n");

	*((__pte_t *)pt_vaddr + idx) = pte;

	return 0;
}

static inline void pte_read(__vaddr_t pt_vaddr, unsigned int lvl,
			    unsigned int idx, __pte_t *pte)
{
	(void)lvl;

#ifdef CONFIG_LIBUKDEBUG
	UK_ASSERT(idx < PT_Lx_PTES(lvl));
#endif /* CONFIG_LIBUKDEBUG */

	*pte = *((__pte_t *)pt_vaddr + idx);
}

static inline void pte_write(__vaddr_t pt_vaddr, unsigned int lvl,
			    unsigned int idx, __pte_t pte)
{
	(void)lvl;

#ifdef CONFIG_LIBUKDEBUG
	UK_ASSERT(idx < PT_Lx_PTES(lvl));
#endif /* CONFIG_LIBUKDEBUG */

	*((__pte_t *)pt_vaddr + idx) = pte;
}

static void blacklist_add(__paddr_t start, __paddr_t end)
{
	if (blacklist_size > 0
	    && start == frame_blacklist[blacklist_size - 1].end) {
		frame_blacklist[blacklist_size - 1].end = end;
	} else {
		UK_ASSERT(blacklist_size < UNIMSG_MAX_BLACKLIST_SIZE);
		frame_blacklist[blacklist_size].start = start;
		frame_blacklist[blacklist_size++].end = end;
	}
}

/**
 * Tags a range of pages with the specified key and adds corresponding physical
 * frames to blacklist to prevent unauthorized mappings.
 * Leverages the fact that consecutive virtual addresses are likely to be mapped
 * to consecutive physical addresses to blacklist frame ranges instead of single
 * frames.
 */
static int set_mpk_key(void *start, void *end, unsigned long key)
{
	struct uk_pagetable *pt = ukplat_pt_get_active();
	__vaddr_t pt_vaddr = pt->pt_vbase;
	__vaddr_t vaddr = (__vaddr_t)start;
	__pte_t pte;
	unsigned int lvl = PT_LEVELS - 1;
	int rc = 0;

	while (vaddr < (__vaddr_t)end) {
again:
		pte_read(pt_vaddr, lvl, PT_Lx_IDX(vaddr, lvl), &pte);
		if (!PT_Lx_PTE_PRESENT(pte, lvl))
			return -ENOENT;

		__paddr_t paddr = PT_Lx_PTE_PADDR(pte, lvl);
		if (!PAGE_Lx_IS(pte, lvl)) {
			/* Go down one level */
			pt_vaddr = x86_directmap_paddr_to_vaddr(paddr);
			lvl--;
			goto again;
		}

		UK_ASSERT(PAGE_Lx_ALIGNED(vaddr, lvl));

		if (((pte & X86_PTE_MPK_MASK) >> 59) == key)
			UK_CRASH("Invalid MPK key modification\n");

		pte &= ~X86_PTE_MPK_MASK;
		pte |= key << 59;
		pte_write(pt_vaddr, lvl, PT_Lx_IDX(vaddr, lvl), pte);
		ukarch_tlb_flush_entry(vaddr);

		blacklist_add(paddr, paddr + PAGE_Lx_SIZE(lvl));

		vaddr += PAGE_Lx_SIZE(lvl);
		if (PT_Lx_IDX(vaddr, lvl) == 0) {
			/* Restart from top level */
			lvl = PT_LEVELS - 1;
			pt_vaddr = pt->pt_vbase;
		}

		/* Handle address wrapping */
		if (vaddr == 0)
			break;
	}

	UK_ASSERT(end == (void *)vaddr || end == (void *)0xffffffffffffffff);

	return rc;
}

/* Addresses for buffer address validation */
static __vaddr_t buffers_start;
static __vaddr_t buffers_end;
#define PT_CACHE_START_VADDR 0x200000000
static __vaddr_t next_buffer_pt_vaddr = PT_CACHE_START_VADDR;
static __vaddr_t buffers_pts[UNIMSG_BUFFERS_COUNT / PT_Lx_PTES(0)];
#define BUFFER_TO_PT_IDX(addr)						\
	(((__vaddr_t)addr - (__vaddr_t)buffers_start)			\
	 / PAGE_SIZE / PT_Lx_PTES(0))

static int cache_ptes(void *start, void *end)
{
	struct uk_pagetable *pt = ukplat_pt_get_active();
	__vaddr_t pt_vaddr = pt->pt_vbase;
	__vaddr_t vaddr = (__vaddr_t)start;
	__pte_t pte;
	unsigned int lvl = PT_LEVELS - 1;
	int rc = 0;
	__paddr_t paddr = 0;

	while (vaddr < (__vaddr_t)end) {
again:
		pte_read(pt_vaddr, lvl, PT_Lx_IDX(vaddr, lvl), &pte);
		if (!PT_Lx_PTE_PRESENT(pte, lvl))
			return -ENOENT;

		if (!PAGE_Lx_IS(pte, lvl)) {
			/* Go down one level */
			paddr = PT_Lx_PTE_PADDR(pte, lvl);
			pt_vaddr = x86_directmap_paddr_to_vaddr(paddr);
			lvl--;
			goto again;
		}

		UK_ASSERT(PAGE_Lx_ALIGNED(vaddr, lvl));

		/* Map the pt to a standard vaddr */
		rc = ukplat_page_map(ukplat_pt_get_active(),
				     next_buffer_pt_vaddr, paddr, 1,
				     PAGE_ATTR_PROT_RW,
				     PAGE_FLAG_SIZE(0) | PAGE_FLAG_FORCE_SIZE);
		if (rc)
			return rc;

		buffers_pts[BUFFER_TO_PT_IDX(vaddr)] = next_buffer_pt_vaddr;
		next_buffer_pt_vaddr += PAGE_SIZE;
		vaddr += PAGE_SIZE * PT_Lx_PTES(0);

		/* Restart from top level */
		lvl = PT_LEVELS - 1;
		pt_vaddr = pt->pt_vbase;
	}

	return rc;
}

static inline void validate_buffer_addr(__vaddr_t addr)
{
	if (addr < buffers_start || addr >= buffers_end)
		UK_CRASH("Detected invalid shm buffer address\n");
}

void set_buffer_access(void *addr, int enabled)
{
	__vaddr_t vaddr = (__vaddr_t)addr;
	unsigned long key = enabled ? UNIMSG_DEFAULT_KEY : UNIMSG_ACCESS_KEY;

	validate_buffer_addr(vaddr);

	__vaddr_t pt_vaddr = buffers_pts[BUFFER_TO_PT_IDX(vaddr)];
	__pte_t pte;
	pte_read(pt_vaddr, 0, PT_Lx_IDX(vaddr, 0), &pte);

	/* The following condition allows to identify forged shm descriptors
	 * that, during a send or put, result in trying to set ACCESS key to
	 * pages already tagged with ACCESS.
	 */
	if (((pte & X86_PTE_MPK_MASK) >> 59) == key)
		UK_CRASH("Invalid MPK key modification\n");

	pte &= ~X86_PTE_MPK_MASK;
	pte |= key << 59;
	pte_write(pt_vaddr, 0, PT_Lx_IDX(vaddr, 0), pte);
	ukarch_tlb_flush_entry(vaddr);
}

/**
 * Adds the physical frame storing the given page table and all nested ones to
 * blacklist to prevent further mappings. Page tables allocated after executing
 * this function will not be protected, but that is not a problem since they
 * won't lead to unimsg pages.
 * TODO: check that the number of page tables detected (~ 1600) makes sense
 */
static void blacklist_page_table(__paddr_t paddr, int lvl)
{
	__pte_t pte;
	__vaddr_t vaddr = x86_directmap_paddr_to_vaddr(paddr);

	blacklist_add(paddr, paddr + PAGE_SIZE);

	if (lvl > PAGE_LEVEL) {
		for (unsigned i = 0; i < PT_Lx_PTES(lvl); i++) {
			pte_read(vaddr, lvl, i, &pte);
			if (PT_Lx_PTE_PRESENT(pte, lvl)
			    && !PAGE_Lx_IS(pte, lvl))
				blacklist_page_table(PT_Lx_PTE_PADDR(pte, lvl),
						     lvl - 1);
		}
	}
}
#endif /* CONFIG_LIBUNIMSG_MEMORY_PROTECTION */

static int unimsg_init()
{
	uk_pr_info("Initialize unimsg...\n");

	struct qemu_ivshmem_info control_ivshmem, buffers_ivshmem,
				 sidecar_ivshmem;

	int rc = qemu_ivshmem_get_info(CONTROL_IVSHMEM_ID, &control_ivshmem);
	if (rc) {
		uk_pr_err("Error retrieving shared memory info: %s\n",
			  strerror(-rc));
		return rc;
	}

	if (control_ivshmem.type != QEMU_IVSHMEM_TYPE_DOORBELL) {
		uk_pr_err("Unexpected QEMU ivshmem device type\n");
		return -EINVAL;
	}

	rc = qemu_ivshmem_get_info(BUFFERS_IVSHMEM_ID, &buffers_ivshmem);
	if (rc) {
		uk_pr_err("Error retrieving shared memory: %s\n",
			  strerror(-rc));
		return rc;
	}

	if (buffers_ivshmem.type != QEMU_IVSHMEM_TYPE_PLAIN) {
		uk_pr_err("Unexpected QEMU ivshmem device type\n");
		return -EINVAL;
	}

	rc = qemu_ivshmem_get_info(SIDECAR_IVSHMEM_ID, &sidecar_ivshmem);
	if (rc) {
		uk_pr_err("Error retrieving shared memory: %s\n",
			  strerror(-rc));
		return rc;
	}

	if (buffers_ivshmem.type != QEMU_IVSHMEM_TYPE_PLAIN) {
		uk_pr_err("Unexpected QEMU ivshmem device type\n");
		return -EINVAL;
	}

	rc = signal_init(control_ivshmem);
	if (rc)
		return rc;

	rc = net_init(control_ivshmem, sidecar_ivshmem);
	if (rc)
		return rc;

	rc = shm_init(control_ivshmem, buffers_ivshmem);
	if (rc)
		return rc;

#ifdef CONFIG_LIBUNIMSG_MEMORY_PROTECTION
	/* Protect library sections */
#define PROTECT_SECTION(name, key) ({					\
	rc = set_mpk_key(_ ## name ## _unimsg_start,			\
			 _ ## name ## _unimsg_end, key);		\
	if (rc) {							\
		uk_pr_err("Error protecting " #name " section\n");	\
		return rc;						\
	}								\
	uk_pr_info("Protected " #name "\n");				\
})
	PROTECT_SECTION(text, UNIMSG_ACCESS_KEY);
	/* TODO: for some reason _rodata_unimsg_end is not page aligned */
	// PROTECT_SECTION(rodata, UNIMSG_ACCESS_KEY);
	rc = set_mpk_key(_rodata_unimsg_start, _rodata_unimsg_start + PAGE_SIZE,
			 UNIMSG_ACCESS_KEY);
	if (rc) {
		uk_pr_err("Error protecting rodata section\n");
		return rc;
	}
	uk_pr_info("Protected rodata\n");
	PROTECT_SECTION(data, UNIMSG_ACCESS_KEY);
	PROTECT_SECTION(bss, UNIMSG_ACCESS_KEY);

	/* Protect the IDT and interrupt return status. From this point on it
	 * won't be possible to change the entry point of ISRs outside unimsg
	 * code
	 */
	PROTECT_SECTION(interrupt, UNIMSG_WRITE_KEY);

	/* Protect shm */
	rc = set_mpk_key(control_ivshmem.addr,
			 control_ivshmem.addr + control_ivshmem.size,
			 UNIMSG_ACCESS_KEY);
	if (rc) {
		uk_pr_err("Error protecting control shm\n");
		return rc;
	}
	uk_pr_info("Protected control shm\n");
	rc = set_mpk_key(buffers_ivshmem.addr,
			 buffers_ivshmem.addr + buffers_ivshmem.size,
			 UNIMSG_ACCESS_KEY);
	if (rc) {
		uk_pr_err("Error protecting buffers shm\n");
		return rc;
	}
	uk_pr_info("Protected buffers shm\n");

	/* Protect sidecar mem */
	rc = set_mpk_key(sidecar_ivshmem.addr,
			 sidecar_ivshmem.addr + sidecar_ivshmem.size,
			 UNIMSG_ACCESS_KEY);
	if (rc) {
		uk_pr_err("Error protecting sidecar memory\n");
		return rc;
	}
	uk_pr_info("Protected sidecar memory\n");

	/* Store addresses for buffer validation */
	buffers_start = (__vaddr_t)buffers_ivshmem.addr;
	buffers_end = (__vaddr_t)buffers_start
		      + UNIMSG_BUFFER_SIZE * UNIMSG_BUFFERS_COUNT;

	/* Cache buffers pte's addresses so we don't have to perform a full walk
	 * of the page table every time we change their MPK key
	 */
	cache_ptes(buffers_ivshmem.addr,
		   buffers_ivshmem.addr
		   + UNIMSG_BUFFER_SIZE * UNIMSG_BUFFERS_COUNT);
	uk_pr_info("Cached buffers page tables\n");

	/* TODO: do we need to protect the memory pointed by other BARs?
	 * What about the configuration space of the device itself
	 */

	/* Create a dedicated heap */
	void *buf = uk_palloc(uk_alloc_get_default(),
			      CONFIG_LIBUNIMSG_HEAP_PAGES);
	if (!buf) {
		uk_pr_err("Insufficient memory to allocate heap");;
		return -ENOMEM;
	}
	unimsg_allocator = uk_alloc_init(buf,
					 CONFIG_LIBUNIMSG_HEAP_PAGES
					 * PAGE_SIZE);
	if (!unimsg_allocator) {
		uk_pr_err("Failed to initialize heap allocator");
		uk_pfree(uk_alloc_get_default(), buf,
			 CONFIG_LIBUNIMSG_HEAP_PAGES);
		return -ENOMEM;
	}
	rc = set_mpk_key(buf, buf + CONFIG_LIBUNIMSG_HEAP_PAGES * PAGE_SIZE,
			 UNIMSG_ACCESS_KEY);
	if (rc) {
		uk_pr_err("Error protecting heap\n");
		unimsg_allocator = NULL;
		uk_pfree(uk_alloc_get_default(), buf,
			 CONFIG_LIBUNIMSG_HEAP_PAGES);
		return rc;
	}
	uk_pr_info("Protected heap\n");

	/* Create a dedicated stack */

	/* Unikraft statically maps the first 512GB of physiscal memory on a
	 * continguous virtual address range (directly mapped area). This is
	 * used for page table to easily convert paddr to vaddr (only need to
	 * add a constant offset). This address range however allows to access
	 * all the memory of the VM, so we need to protect it. It would be nice
	 * to only protect page tables with WRITE_KEY, so that a PTE can be read
	 * without escalating privilege. However, this direct mapped are uses 1G
	 * pages, so page tables share the same page with other data and we need
	 * to use ACCESS_KEY
	 */
	rc = set_mpk_key((void *)DIRECTMAP_AREA_START,
			 (void *)DIRECTMAP_AREA_END, UNIMSG_ACCESS_KEY);
	if (rc) {
		uk_pr_err("Error protecting directly mapped area\n");
		unimsg_allocator = NULL;
		uk_pfree(uk_alloc_get_default(), buf,
			 CONFIG_LIBUNIMSG_HEAP_PAGES);
		return rc;
	}
	uk_pr_info("Protected directly mapped area\n");

	/* Blacklist page table frames */
	struct uk_pagetable *pt = ukplat_pt_get_active();
	blacklist_page_table(pt->pt_pbase, PT_LEVELS);

	uk_pr_info("%u ranges added to the blacklist\n", blacklist_size);

	/* Populate thread infos freelist */
	struct thread_info *ti = NULL;
	for (int i = 0; i < CONFIG_LIBUNIMSG_MAX_THREADS; i++) {
		thread_infos[i].freelist_next = ti;
		ti = &thread_infos[i];
	}
	thread_info_freelist = ti;

	/* Register all threads created prior to unimsg initialization */
	initialized = 1;
	struct thread_to_register *tr_prev, *tr = threads_to_register;
	while (tr != NULL) {
		rc = _unimsg_thread_register(tr->t);
		if (rc)
			return rc;
		tr_prev = tr;
		tr = tr->next;
		uk_free(uk_alloc_get_default(), tr_prev);
	}

	/* Disable access to unimsg pages */
	__builtin_ia32_wrpkru(UNIMSG_PKRU_DEFAULT);
	/* TODO: I think this is subject to ROP, write it in ASM with check */

#else /* !CONFIG_LIBUNIMSG_MEMORY_PROTECTION */
	unimsg_allocator = uk_alloc_get_default();
#endif /* CONFIG_LIBUNIMSG_MEMORY_PROTECTION */

	return 0;
}
uk_lib_initcall(unimsg_init);