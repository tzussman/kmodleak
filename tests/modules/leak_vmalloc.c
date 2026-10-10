// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/module.h>
#include <linux/vmalloc.h>

static void *ptr;

static int __init leak_vmalloc_init(void)
{
	pr_info("Loading leak_vmalloc module...\n");
	ptr = vmalloc(1 << 20);
	return 0;
}

static void __exit leak_vmalloc_exit(void)
{
	pr_info("Unloading leak_vmalloc module...\n");
}

module_init(leak_vmalloc_init);
module_exit(leak_vmalloc_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Test module leaking a vmalloc() allocation");
MODULE_AUTHOR("Tal Zussman");
