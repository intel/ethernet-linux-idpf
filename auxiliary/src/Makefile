# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2019-2025 Intel Corporation


ifneq ($(KERNELRELEASE),)
# kbuild part of makefile
#
# Makefile for Intel(R) Infrastructure Data Path Function Linux Driver
#

ifeq (${NEED_AUX_BUS},2)
obj-$(CONFIG_AUXILIARY) += auxiliary.o
endif

auxiliary-y := \
	_auxiliary.o
auxiliary-y += kcompat.o
else	# ifneq($(KERNELRELEASE),)
# normal makefile

DRIVER := auxiliary

AUX_BUS_HEADER := ./auxiliary_bus.h
CHECK_AUX_BUS := ../../check_aux_bus
COMMON_MK ?= $(wildcard common.mk)
ifeq (${COMMON_MK},)
  $(error Cannot find common.mk build rules)
else
  include ${COMMON_MK}
endif

# auxiliary does not support building on kernels older than 3.10.0
$(call minimum_kver_check,3,10,0)

# Command to update initramfs or display a warning message
ifeq (${cmd_initrd},)
define cmd_initramfs
@echo "Unable to update initramfs. You may need to do this manaully."
endef
else
define cmd_initramfs
@echo "Updating initramfs..."
$(call cmd_initrd)
endef
endif

all:
	+$(call kernelbuild,modules)
	@gzip -c ../${DRIVER}.${MANSECTION} > ${DRIVER}.${MANSECTION}.gz

clean:
	+$(call kernelbuild,clean)
	@-rm -rf *.${MANSECTION}.gz *.ko

# Install kernel module files. This target is called by the RPM specfile when
# generating binary RPMs, and is not expected to modify files outside of the
# build root. Thus, it must not update initramfs, or run depmod.
modules_install: all
	$(call kernelbuild,modules_install)
	${auxiliary_post_install}

mandocs_install: all
	install -D -m 644 ${DRIVER}.${MANSECTION}.gz ${INSTALL_MOD_PATH}${MANDIR}/man${MANSECTION}/${DRIVER}.${MANSECTION}.gz

auxiliary_info:
	@../../check_aux_bus --verbose --ksrc="${KSRC}" --build-kernel="${BUILD_KERNEL}"

ifeq (${NEED_AUX_BUS},1)
all: auxiliary_info
endif

# After installing all the files, perform necessary work to ensure the system
# will use the new modules. This includes running depmod to update module
# dependencies and updating the initramfs image in case the module is loaded
# during early boot.
install: modules_install mandocs_install
	$(call cmd_depmod)
	$(call cmd_initramfs)

# Remove installed module files. This target is called by the RPM specfile when
# generating binary RPMs, and is not expected to modify files outside of the
# build root. Thus, it must not update the initramfs image or run depmod.
modules_uninstall:
	rm -f ${INSTALL_MOD_PATH}/lib/modules/${KVER}/${INSTALL_MOD_DIR}/${DRIVER}.ko

mandocs_uninstall:
	rm -f ${INSTALL_MOD_PATH}${MANDIR}/man${MANSECTION}/${DRIVER}.${MANSECTION}.gz 2>/dev/null

# After uninstalling all the files, perform necessary work to restore the
# system back to using the default kernel modules. This includes running depmod
# to update module dependencies and updating the initramfs image.
uninstall: modules_uninstall mandocs_uninstall
	$(call cmd_depmod)
	$(call cmd_initramfs)

help:
	@echo 'Building external (out-of-tree) modules:'
	@echo '  all               - default target, build the module(s) and manpage'
	@echo '  clean             - remove generated files'
	@echo '  modules_install   - install the module(s) only'
	@echo '  mandocs_install   - install the manpage only'
	@echo '  install           - install the module(s) and manpage, and update initramfs'
	@echo '  modules_uninstall - uninstall the module(s) only'
	@echo '  mandocs_uninstall - uninstall the manpage only'
	@echo '  uninstall         - uninstall the module(s) and manpage, and update initramfs'
	@echo '  auxiliary_info    - print information about the auxiliary module'
	@echo ''
	@echo 'Command-line options:'
	@echo '  KSRC=<path>     - Path to kernel source (defaults to running kernel)'
	@echo '  LINUX_VERSION=<x.y.z> - Debug tool to force kernel LINUX_VERSION_CODE for'
	@echo '                          external module(s).  *** Use at your own risk! ***'
	@echo '  INSTALL_MOD_PATH=<path> - Prefix added to default module(s) installation path'
	@echo '                            (/lib/modules/$$(KERNELRELEASE)/)'
	@echo '  INSTALL_MOD_DIR=<path> - Install module(s) in subdirectory other than default'
	@echo '                           (.../updates/drivers/net/ethernet/intel/${DRIVER}/)'
	@echo ''

.PHONY: all clean modules_install mandocs_install install modules_uninstall mandocs_uninstall uninstall help auxiliary_info

endif	# ifneq($(KERNELRELEASE),)
