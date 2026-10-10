// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/workqueue.h>

/* Leaks from a work item, i.e. a kworker rather than the loading process */

static void *ptr;

static void leak_work_fn(struct work_struct *work)
{
	pr_info("leak_work: allocating\n");
	ptr = kmalloc(100, GFP_KERNEL);
}

static DECLARE_WORK(leak_work, leak_work_fn);

static int __init leak_work_init(void)
{
	pr_info("Loading leak_work module...\n");
	schedule_work(&leak_work);
	return 0;
}

static void __exit leak_work_exit(void)
{
	pr_info("Unloading leak_work module...\n");
	flush_work(&leak_work);
}

module_init(leak_work_init);
module_exit(leak_work_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Test module leaking from a work item");
MODULE_AUTHOR("Tal Zussman");
