obj-m += leak.o noleak.o
obj-m += leak_multi.o leak_large.o
obj-m += leak_pages.o noleak_pages.o noleak_pages_fail.o
obj-m += leak_vmalloc.o noleak_vmalloc.o
obj-m += leak_percpu.o
obj-m += leak_core.o
obj-m += leak_work.o
obj-m += noleak_xctx.o
obj-m += cache_alloc.o
obj-m += leak_initfail.o
obj-m += leak_with_the_longest_module_name_the_kernel_permits_xx.o
obj-m += leak-dash.o
obj-m += noleak_rcu.o

KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules
clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
