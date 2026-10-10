// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/module.h>
#include <linux/slab.h>

/* Leaks and then fails to initialize, so the module is freed without exit */

static void *ptr;

static int __init leak_initfail_init(void)
{
	pr_info("Loading leak_initfail module...\n");
	ptr = kmalloc(100, GFP_KERNEL);
	return -EINVAL;
}

module_init(leak_initfail_init);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Test module leaking from a failing init");
MODULE_AUTHOR("Tal Zussman");
