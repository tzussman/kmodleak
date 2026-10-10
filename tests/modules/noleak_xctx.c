// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/workqueue.h>

/* Allocates in init and frees from a work item, i.e. a different context */

static void *ptr;

static void free_work_fn(struct work_struct *work)
{
	pr_info("noleak_xctx: freeing\n");
	kfree(ptr);
}

static DECLARE_WORK(free_work, free_work_fn);

static int __init noleak_xctx_init(void)
{
	pr_info("Loading noleak_xctx module...\n");
	ptr = kmalloc(100, GFP_KERNEL);
	schedule_work(&free_work);
	return 0;
}

static void __exit noleak_xctx_exit(void)
{
	pr_info("Unloading noleak_xctx module...\n");
	flush_work(&free_work);
}

module_init(noleak_xctx_init);
module_exit(noleak_xctx_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Test module freeing from a different context than it allocated in");
MODULE_AUTHOR("Tal Zussman");
