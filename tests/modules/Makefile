obj-m += leak.o noleak.o
obj-m += leak_multi.o
obj-m += leak_pages.o noleak_pages.o
obj-m += leak_percpu.o
obj-m += leak_core.o
obj-m += leak_work.o
obj-m += noleak_xctx.o
obj-m += cache_alloc.o

KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules
clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
