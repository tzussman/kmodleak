// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/module.h>
#include <linux/slab.h>

/*
 * Allocates from a private slab cache and holds the object until exit, so
 * that it shows up as outstanding while the module is loaded. The cache
 * cannot be leaked across unload, since kmem_cache_destroy() refuses to
 * destroy a cache with live objects.
 */

static struct kmem_cache *cache;
static void *obj;

static int __init cache_alloc_init(void)
{
	pr_info("Loading cache_alloc module...\n");
	cache = kmem_cache_create("cache_alloc_test", 64, 0, 0, NULL);
	if (!cache)
		return -ENOMEM;
	obj = kmem_cache_alloc(cache, GFP_KERNEL);
	return 0;
}

static void __exit cache_alloc_exit(void)
{
	pr_info("Unloading cache_alloc module...\n");
	kmem_cache_free(cache, obj);
	kmem_cache_destroy(cache);
}

module_init(cache_alloc_init);
module_exit(cache_alloc_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Test module allocating from a private slab cache");
MODULE_AUTHOR("Tal Zussman");
