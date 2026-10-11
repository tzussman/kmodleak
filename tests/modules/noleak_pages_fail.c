// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/module.h>
#include <linux/gfp.h>
#include <linux/mmzone.h>
#include <linux/version.h>

#ifndef MAX_PAGE_ORDER
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
#define MAX_PAGE_ORDER MAX_ORDER
#else
#define MAX_PAGE_ORDER (MAX_ORDER - 1)
#endif
#endif

/*
 * Allocate the largest order the page allocator serves, without sleeping,
 * until it fails, then free everything. The failed attempt must not be
 * reported as a leak. Each block holds the address of the previous one.
 */
static int __init noleak_pages_fail_init(void)
{
	unsigned long *head = NULL;
	unsigned long *block;
	unsigned long n = 0;

	pr_info("Loading noleak_pages_fail module...\n");

	while ((block = (unsigned long *)__get_free_pages(GFP_NOWAIT | __GFP_NOWARN,
							  MAX_PAGE_ORDER))) {
		*block = (unsigned long)head;
		head = block;
		n++;
	}

	while (head) {
		block = (unsigned long *)*head;
		free_pages((unsigned long)head, MAX_PAGE_ORDER);
		head = block;
	}

	pr_info("noleak_pages_fail: allocated and freed %lu order-%d blocks\n",
		n, MAX_PAGE_ORDER);
	return 0;
}

static void __exit noleak_pages_fail_exit(void)
{
	pr_info("Unloading noleak_pages_fail module...\n");
}

module_init(noleak_pages_fail_init);
module_exit(noleak_pages_fail_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Test that a failed page allocation is not reported as a leak");
MODULE_AUTHOR("Tal Zussman");
