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
int sock_init(struct qemu_ivshmem_info ivshmem);
int shm_init(struct qemu_ivshmem_info control_ivshmem,
	     struct qemu_ivshmem_info buffers_ivshmem);

struct uk_alloc *h2os_allocator;

#ifdef CONFIG_LIBH2OS_MEMORY_PROTECTION
#include <uk/plat/paging.h>

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

#define H2OS_HEAP_PAGES 16
#define H2OS_MAX_BLACKLIST_SIZE 128

struct frame_range {
	__paddr_t start;
	__paddr_t end; /* First frame after the range */
};

static struct frame_range frame_blacklist[H2OS_MAX_BLACKLIST_SIZE];
static unsigned blacklist_size = 0;

extern char _text_h2os_start[], _text_h2os_end[];
extern char _rodata_h2os_start[], _rodata_h2os_end[];
extern char _data_h2os_start[], _data_h2os_end[];
extern char _bss_h2os_start[], _bss_h2os_end[];
extern char _idt_h2os_start[], _idt_h2os_end[];

int h2os_check_frame_protected(__paddr_t addr)
{
	for (unsigned i = 0; i < blacklist_size; i++)
		if (addr >= frame_blacklist[i].start
		    && addr < frame_blacklist[i].end)
			return 1;

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
		UK_ASSERT(blacklist_size < H2OS_MAX_BLACKLIST_SIZE);
		frame_blacklist[blacklist_size].start = start;
		frame_blacklist[blacklist_size++].end = end;
	}
}

/**
 * Tags a range of pages with the specified key and optionally adds
 * corresponding physical frames to blacklist to prevent unauthorized mappings.
 * Leverages the fact that consecutive virtual addresses are likely to be mapped
 * to consecutive physical addresses to blacklist frame ranges instead of single
 * frames.
 */
static int set_mpk_key(void *start, void *end, unsigned long key, int blacklist)
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

		pte &= ~X86_PTE_MPK_MASK;
		pte |= key << 59;
		pte_write(pt_vaddr, lvl, PT_Lx_IDX(vaddr, lvl), pte);
		ukarch_tlb_flush_entry(vaddr);

		// uk_pr_info("Set key on page 0x%lx at lvl %u\n", vaddr, lvl);

		if (blacklist)
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

int enable_buffer_access(struct h2os_shm_desc desc)
{
	return set_mpk_key(buffer_get_addr(desc),
			   buffer_get_addr(desc) + H2OS_SHM_BUFFER_SIZE,
			   H2OS_DEFAULT_KEY, 0);
}

int disable_buffer_access(struct h2os_shm_desc desc)
{
	return set_mpk_key(buffer_get_addr(desc),
			   buffer_get_addr(desc) + H2OS_SHM_BUFFER_SIZE,
			   H2OS_ACCESS_KEY, 0);
}

/**
 * Adds the physical frame storing the given page table and all nested ones to
 * blacklist to prevent further mappings. Page tables allocated after executing
 * this function will not be protected, but that is not a problem since they
 * won't lead to h2os pages.
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
#endif /* CONFIG_LIBH2OS_MEMORY_PROTECTION */

static int h2os_init()
{
	uk_pr_info("Initialize H2OS...\n");

	struct qemu_ivshmem_info control_ivshmem, buffers_ivshmem;

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

	rc = signal_init(control_ivshmem);
	if (rc)
		return rc;

	rc = sock_init(control_ivshmem);
	if (rc)
		return rc;

	rc = shm_init(control_ivshmem, buffers_ivshmem);
	if (rc)
		return rc;

#ifdef CONFIG_LIBH2OS_MEMORY_PROTECTION
	/* We might be in unprivileged mode due to calls to pte_read/write */
	h2os_set_privilege();

	/* Protect library sections */
#define PROTECT_SECTION(name, key) ({					\
	rc = set_mpk_key(_ ## name ## _h2os_start,			\
			 _ ## name ## _h2os_end, key, 1);		\
	if (rc) {							\
		uk_pr_err("Error protecting " #name " section\n");	\
		return rc;						\
	}								\
	uk_pr_info("Protected " #name "\n");				\
})
	PROTECT_SECTION(text, H2OS_ACCESS_KEY);
	/* TODO: for some reason _rodata_h2os_end is not page aligned */
	// PROTECT_SECTION(rodata, H2OS_ACCESS_KEY);
	rc = set_mpk_key(_rodata_h2os_start, _rodata_h2os_start + PAGE_SIZE,
			 H2OS_ACCESS_KEY, 1);
	if (rc) {
		uk_pr_err("Error protecting rodata section\n");
		return rc;
	}
	uk_pr_info("Protected rodata\n");
	PROTECT_SECTION(data, H2OS_ACCESS_KEY);
	PROTECT_SECTION(bss, H2OS_ACCESS_KEY);

	/* Protect the IDT, from this point on it won't be possible to change
	 * the entry point of ISRs otside h2os code
	 */
	PROTECT_SECTION(idt, H2OS_WRITE_KEY);

	/* Protect shm */
	rc = set_mpk_key(control_ivshmem.addr,
			 control_ivshmem.addr + control_ivshmem.size,
			 H2OS_ACCESS_KEY, 1);
	if (rc) {
		uk_pr_err("Error protecting control shm\n");
		return rc;
	}
	uk_pr_info("Protected control shm\n");
	rc = set_mpk_key(buffers_ivshmem.addr,
			 buffers_ivshmem.addr + buffers_ivshmem.size,
			 H2OS_ACCESS_KEY, 1);
	if (rc) {
		uk_pr_err("Error protecting buffers shm\n");
		return rc;
	}
	uk_pr_info("Protected buffers shm\n");

	/* TODO: do we need to protect the memory pointed by other BARs?
	 * What about the configuration space of the device itself
	 */

	/* Create a dedicated heap */
	void *buf = uk_palloc(uk_alloc_get_default(), H2OS_HEAP_PAGES);
	if (!buf) {
		uk_pr_err("Insufficient memory to allocate heap");;
		return -ENOMEM;
	}
	h2os_allocator = uk_alloc_init(buf, H2OS_HEAP_PAGES * PAGE_SIZE);
	if (!h2os_allocator) {
		uk_pr_err("Failed to initialize heap allocator");
		uk_pfree(uk_alloc_get_default(), buf, H2OS_HEAP_PAGES);
		return -ENOMEM;
	}
	rc = set_mpk_key(buf, buf + H2OS_HEAP_PAGES * PAGE_SIZE,
			 H2OS_ACCESS_KEY, 1);
	if (rc) {
		uk_pr_err("Error protecting heap\n");
		h2os_allocator = NULL;
		uk_pfree(uk_alloc_get_default(), buf, H2OS_HEAP_PAGES);
		return rc;
	}
	uk_pr_info("Protected heap\n");

	/* Create a dedicated stack */

	uk_pr_info("PKRU=0x%x\n", __builtin_ia32_rdpkru());

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
			 (void *)DIRECTMAP_AREA_END, H2OS_ACCESS_KEY, 1);
	if (rc) {
		uk_pr_err("Error protecting directly mapped area\n");
		h2os_allocator = NULL;
		uk_pfree(uk_alloc_get_default(), buf, H2OS_HEAP_PAGES);
		return rc;
	}
	uk_pr_info("Protected directly mapped area\n");

	/* Blacklist page table frames */
	struct uk_pagetable *pt = ukplat_pt_get_active();
	blacklist_page_table(pt->pt_pbase, PT_LEVELS);

	uk_pr_info("%u ranges added to the blacklist\n", blacklist_size);

	/* Disable access to h2os pages */
	h2os_reset_privilege();

#else /* !CONFIG_LIBH2OS_MEMORY_PROTECTION */
	h2os_allocator = uk_alloc_get_default();
#endif /* CONFIG_LIBH2OS_MEMORY_PROTECTION */

	return 0;
}
uk_lib_initcall(h2os_init);