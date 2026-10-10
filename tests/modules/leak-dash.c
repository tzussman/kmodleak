// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/module.h>
#include <linux/slab.h>

/* A copy of leak whose file name has a dash; the kernel names it leak_dash */

static void *ptr;

static int __init leak_dash_init(void)
{
	pr_info("Loading leak_dash module...\n");
	ptr = kmalloc(100, GFP_KERNEL);
	return 0;
}

static void __exit leak_dash_exit(void)
{
	pr_info("Unloading leak_dash module...\n");
}

module_init(leak_dash_init);
module_exit(leak_dash_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Test module with a dash in its file name");
MODULE_AUTHOR("Tal Zussman");
