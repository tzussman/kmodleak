// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/module.h>
#include <linux/percpu.h>

static int __percpu *counter;

static int __init leak_percpu_init(void)
{
	pr_info("Loading leak_percpu module...\n");
	counter = alloc_percpu(int);
	return 0;
}

static void __exit leak_percpu_exit(void)
{
	pr_info("Unloading leak_percpu module...\n");
}

module_init(leak_percpu_init);
module_exit(leak_percpu_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Test module leaking a per-CPU allocation");
MODULE_AUTHOR("Tal Zussman");
