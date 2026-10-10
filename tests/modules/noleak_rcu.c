// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>

/* Frees with kfree_rcu() in exit, which lands after the module is gone */

struct obj {
	struct rcu_head rcu;
	char data[64];
};

static struct obj *obj;

static int __init noleak_rcu_init(void)
{
	pr_info("Loading noleak_rcu module...\n");
	obj = kmalloc(sizeof(*obj), GFP_KERNEL);
	return 0;
}

static void __exit noleak_rcu_exit(void)
{
	pr_info("Unloading noleak_rcu module...\n");
	kfree_rcu(obj, rcu);
}

module_init(noleak_rcu_init);
module_exit(noleak_rcu_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Test module freeing with kfree_rcu() in exit");
MODULE_AUTHOR("Tal Zussman");
