// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/module.h>
#include <linux/gfp.h>

static unsigned long pages;

static int __init noleak_pages_init(void)
{
	pr_info("Loading noleak_pages module...\n");
	pages = __get_free_pages(GFP_KERNEL, 1);
	return 0;
}

static void __exit noleak_pages_exit(void)
{
	pr_info("Unloading noleak_pages module...\n");
	free_pages(pages, 1);
}

module_init(noleak_pages_init);
module_exit(noleak_pages_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Test freeing an order-1 page allocation");
MODULE_AUTHOR("Tal Zussman");
