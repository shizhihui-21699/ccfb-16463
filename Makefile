# Tiny reference build. For a Yocto/Buildroot product, package gw-init in the
# BSP image instead of using this install target directly.

ifneq ($(CROSS_COMPILE),)
CC := $(CROSS_COMPILE)gcc
STRIP := $(CROSS_COMPILE)strip
else
CC ?= cc
STRIP ?= strip
endif

CFLAGS ?= -Os -Wall -Wextra -Werror -ffunction-sections -fdata-sections
ifeq ($(shell uname -s),Linux)
LDFLAGS ?= -Wl,--gc-sections
else
LDFLAGS ?=
endif
PREFIX ?=
DESTDIR ?=

.PHONY: all check clean install

all: build/gw-init

build:
	mkdir -p build

build/gw-init: src/gw-init.c | build
	$(CC) $(CFLAGS) -std=c11 -o $@ $< $(LDFLAGS)
	-$(STRIP) $@ 2>/dev/null || true

# Host syntax build plus shell syntax checks.
check: | build
	$(CC) $(CFLAGS) -std=c11 -o build/gw-init-host src/gw-init.c
	sh -n rootfs/etc/gw/load-early-modules
	sh -n rootfs/usr/sbin/gw-boot-confirm
	sh -n scripts/gw-sign-module
	@echo "syntax checks passed"

install: all
	install -d $(DESTDIR)/sbin
	install -d $(DESTDIR)/etc/gw/boot-checks.d
	install -d $(DESTDIR)/etc/init.d
	install -d $(DESTDIR)/usr/sbin
	install -d $(DESTDIR)/lib/systemd/system
	install -d $(DESTDIR)/usr/share/doc/gateway-security
	install -m 0755 build/gw-init $(DESTDIR)/sbin/gw-init
	install -m 0755 rootfs/etc/gw/load-early-modules $(DESTDIR)/etc/gw/
	install -m 0644 rootfs/etc/gw/early-modules $(DESTDIR)/etc/gw/
	install -m 0644 rootfs/etc/gw/protected.list $(DESTDIR)/etc/gw/
	install -m 0644 rootfs/etc/gw/sysctl.lock $(DESTDIR)/etc/gw/
	install -m 0644 rootfs/etc/gw/boot.conf $(DESTDIR)/etc/gw/
	install -m 0755 rootfs/usr/sbin/gw-boot-confirm $(DESTDIR)/usr/sbin/
	install -m 0644 systemd/gw-boot-confirm.service \
		$(DESTDIR)/lib/systemd/system/
	install -m 0644 README.md docs/ROLLOUT.md \
		$(DESTDIR)/usr/share/doc/gateway-security/

clean:
	rm -rf build
