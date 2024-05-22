#include <linux/module.h>
#include <linux/slab.h>

void *ptr;

int noleak_init(void)
{
    pr_info("Loading noleak module...\n");
    ptr = kmalloc(100, GFP_KERNEL);
    return 0;
}

void noleak_exit(void)
{
    pr_info("Unloading noleak module...\n");
    kfree(ptr);
}

module_init(noleak_init);
module_exit(noleak_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Test noleak module");
MODULE_AUTHOR("Tal Zussman");
