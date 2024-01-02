MODNAME ?= rootkit
include $(PWD)/Makefile.khook
$(MODNAME)-y += $(KHOOK_GOALS)
ccflags-y    += $(KHOOK_CCFLAGS)
ldflags-y    += $(KHOOK_LDFLAGS)

obj-m := diamorphine.o
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
