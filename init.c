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
#define SECURE_SECTION(name) ({						\
	rc = h2os_set_pages_access((__vaddr_t)_ ## name ## _h2os_start,	\
				   (_ ## name ## _h2os_end		\
				    - _ ## name ## _h2os_start)		\
				   / PAGE_SIZE,	0);			\
	if (rc) {							\
		uk_pr_err("Error securing " #name " section\n");	\
		return rc;						\
	}								\
})

extern char _text_h2os_start[], _text_h2os_end[];
extern char _rodata_h2os_start[], _rodata_h2os_end[];
extern char _data_h2os_start[], _data_h2os_end[];
extern char _bss_h2os_start[], _bss_h2os_end[];

static inline int h2os_pte_write(__vaddr_t pt_vaddr, unsigned int lvl,
				 unsigned int idx, __pte_t pte)
{
	(void)lvl;

#ifdef CONFIG_LIBUKDEBUG
	UK_ASSERT(idx < PT_Lx_PTES(lvl));
#endif /* CONFIG_LIBUKDEBUG */

	*((__pte_t *)pt_vaddr + idx) = pte;

	return 0;
}

static int h2os_set_pages_access(__vaddr_t start, unsigned npages, int enabled)
{
	for (unsigned i = 0; i < npages; i++) {
		__pte_t pte;
		__vaddr_t pt_vaddr, pgaddr = start + i * PAGE_SIZE;
		unsigned int level = PAGE_LEVEL;

		if (ukplat_pt_walk(ukplat_pt_get_active(), pgaddr, &level,
				   &pt_vaddr, &pte)) {
			uk_pr_err("Page %u not found (%lx)\n", i, pgaddr);
			return -ENOENT;
		}

		if (enabled)
			pte &= ~X86_PTE_MPK_MASK;
		else
			pte |= H2OS_MPK_KEY << 59;

		h2os_pte_write(pt_vaddr, level, PT_Lx_IDX(pgaddr, level), pte);
	}

	return 0;
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
	/* Secure library sections */
	SECURE_SECTION(text);
	SECURE_SECTION(rodata);
	SECURE_SECTION(data);
	SECURE_SECTION(bss);

	/* Secure shm */
	rc = h2os_set_pages_access((__vaddr_t)control_ivshmem.addr,
				   control_ivshmem.size / PAGE_SIZE, 0);
	if (rc) {
		uk_pr_err("Error securing control shm\n");
		return rc;
	}
	rc = h2os_set_pages_access((__vaddr_t)buffers_ivshmem.addr,
				   buffers_ivshmem.size / PAGE_SIZE, 0);
	if (rc) {
		uk_pr_err("Error securing buffers shm\n");
		return rc;
	}

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
	rc = h2os_set_pages_access((__vaddr_t)buf, H2OS_HEAP_PAGES, 0);
	if (rc) {
		uk_pr_err("Error securing heap\n");
		h2os_allocator = NULL;
		uk_pfree(uk_alloc_get_default(), buf, H2OS_HEAP_PAGES);
		return rc;
	}

	/* Create a dedicated stack */

	/* Disable access to h2os pages */
	H2OS_DISABLE_ACCESS();
#else /* !CONFIG_LIBH2OS_MEMORY_PROTECTION */
	h2os_allocator = uk_alloc_get_default();
#endif /* CONFIG_LIBH2OS_MEMORY_PROTECTION */

	return 0;
}
uk_lib_initcall(h2os_init);