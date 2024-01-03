KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
KHOOK_DIR := $(shell dirname $(shell realpath --relative-to=$(PWD) $(lastword $(MAKEFILE_LIST))))

diamorph-y := $(KHOOK_DIR)/khook/engine.o $(KHOOK_DIR)/khook/x86/hook.o $(KHOOK_DIR)/khook/x86/stub.o diamorphine.o
ccflags-y := -I$(PWD)/$(KHOOK_DIR) $(call cc-option,-fcf-protection=none)
ldflags-y := -T$(PWD)/$(KHOOK_DIR)/khook/engine.lds
obj-m := diamorph.o

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
