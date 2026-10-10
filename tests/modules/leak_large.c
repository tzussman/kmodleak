// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/module.h>
#include <linux/slab.h>

/* Leaks a kmalloc too large for a slab cache, which is backed by pages */

static void *ptr;

static int __init leak_large_init(void)
{
	pr_info("Loading leak_large module...\n");
	ptr = kmalloc(256 * 1024, GFP_KERNEL);
	return 0;
}

static void __exit leak_large_exit(void)
{
	pr_info("Unloading leak_large module...\n");
}

module_init(leak_large_init);
module_exit(leak_large_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Test module leaking a large kmalloc");
MODULE_AUTHOR("Tal Zussman");
