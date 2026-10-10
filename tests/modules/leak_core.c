// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/slab.h>

/*
 * Leaks from core text rather than init text: writing to the trigger
 * parameter after the module is loaded allocates and never frees.
 */

static void *ptr;

static int trigger_set(const char *val, const struct kernel_param *kp)
{
	pr_info("leak_core: allocating\n");
	ptr = kmalloc(100, GFP_KERNEL);
	return 0;
}

static const struct kernel_param_ops trigger_ops = {
	.set = trigger_set,
};

module_param_cb(trigger, &trigger_ops, NULL, 0200);

static int __init leak_core_init(void)
{
	pr_info("Loading leak_core module...\n");
	return 0;
}

static void __exit leak_core_exit(void)
{
	pr_info("Unloading leak_core module...\n");
}

module_init(leak_core_init);
module_exit(leak_core_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Test module leaking from a parameter callback");
MODULE_AUTHOR("Tal Zussman");
