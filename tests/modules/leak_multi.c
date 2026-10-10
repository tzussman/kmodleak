// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/module.h>
#include <linux/slab.h>

/* Allocates nr_allocs objects from one call site so that they aggregate */

static unsigned int nr_allocs = 10;
module_param(nr_allocs, uint, 0444);

static int __init leak_multi_init(void)
{
	unsigned int i;

	pr_info("Loading leak_multi module...\n");
	for (i = 0; i < nr_allocs; i++)
		kmalloc(64, GFP_KERNEL);
	return 0;
}

static void __exit leak_multi_exit(void)
{
	pr_info("Unloading leak_multi module...\n");
}

module_init(leak_multi_init);
module_exit(leak_multi_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Test module leaking several allocations from one stack");
MODULE_AUTHOR("Tal Zussman");
