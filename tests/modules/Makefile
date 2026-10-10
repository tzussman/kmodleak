obj-m += leak.o noleak.o
obj-m += leak_multi.o
obj-m += leak_pages.o noleak_pages.o
obj-m += leak_percpu.o

KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules
clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
