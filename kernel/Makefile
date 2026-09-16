obj-m += kernel_tasks.o

# KDIR points to the kernel headers directory. 
# Defaults to the currently running kernel's build directory.
KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
