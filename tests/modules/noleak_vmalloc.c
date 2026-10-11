// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/module.h>
#include <linux/vmalloc.h>

static void *ptr;

static int __init noleak_vmalloc_init(void)
{
	pr_info("Loading noleak_vmalloc module...\n");
	ptr = vmalloc(1 << 20);
	return 0;
}

static void __exit noleak_vmalloc_exit(void)
{
	pr_info("Unloading noleak_vmalloc module...\n");
	vfree(ptr);
}

module_init(noleak_vmalloc_init);
module_exit(noleak_vmalloc_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Test module freeing a vmalloc() allocation");
MODULE_AUTHOR("Tal Zussman");
