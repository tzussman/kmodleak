#include <linux/module.h>
#include <linux/slab.h>

void *ptr;

int leak_init(void)
{
    pr_info("Loading leak module...\n");
    ptr = kmalloc(100, GFP_KERNEL);
    return 0;
}

void leak_exit(void)
{
    pr_info("Unloading leak module...\n");
    //kfree(ptr);
}

module_init(leak_init);
module_exit(leak_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Test leak module");
MODULE_AUTHOR("Tal Zussman");
