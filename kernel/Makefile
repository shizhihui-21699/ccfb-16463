# External-module Makefile for the optional gw_regbroker template.
#
# Build on the kernel build host:
#   make -C kernel KDIR=/path/to/configured/kernel/build
#
# Then sign the resulting gw_regbroker.ko with scripts/gw-sign-module.

ifneq ($(KERNELRELEASE),)
obj-m := gw_regbroker.o
else

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

.PHONY: all modules clean

all modules:
	$(MAKE) -C "$(KDIR)" M="$(PWD)" modules

clean:
	$(MAKE) -C "$(KDIR)" M="$(PWD)" clean

endif
