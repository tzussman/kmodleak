// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/module.h>
#include <linux/slab.h>

/* A copy of leak with a MODULE_NAME_LEN - 1 character name */

static void *ptr;

static int __init longname_init(void)
{
	pr_info("Loading long name module...\n");
	ptr = kmalloc(100, GFP_KERNEL);
	return 0;
}

static void __exit longname_exit(void)
{
	pr_info("Unloading long name module...\n");
}

module_init(longname_init);
module_exit(longname_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Test module with the longest permitted name");
MODULE_AUTHOR("Tal Zussman");
