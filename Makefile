# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2021 Intel Corporation

TARGETS := idpf auxiliary
VERSION := 1.0.2

# Shortcut version target
ifneq ($(filter version,${MAKECMDGOALS}),)
.PHONY: ${MAKECMDGOALS}
version:
	@echo ${VERSION}

$(filter-out version,${MAKECMDGOALS}):
	@true

else # version target handling
ifneq (${KERNELRELEASE},)
# Kbuild part of makefile
obj-y := $(strip $(addsuffix /src/,${TARGETS}))
ccflags-y += -I$(src)
subdir-ccflags-y += -I$(src)
else # ifneq (${KERNELRELEASE},)
# normal make

# Default to using updates/drivers/net/ethernet/intel/ path, since depmod since
# v3.1 defaults to checking updates folder first, and only checking kernels/
# and extra afterwards. We use updates instead of kernel/* due to desire to
# prevent over-writing built-in modules files.
export INSTALL_MOD_DIR ?= updates/drivers/net/ethernet/intel/

ifeq (${BUILD_KERNEL},)
BUILD_KERNEL=$(shell uname -r)
endif
# Kernel Search Path
# All the places we look for kernel source
KSP :=  /lib/modules/${BUILD_KERNEL}/source \
        /lib/modules/${BUILD_KERNEL}/build \
        /usr/src/linux-${BUILD_KERNEL} \
        /usr/src/linux-$(${BUILD_KERNEL} | sed 's/-.*//') \
        /usr/src/kernel-headers-${BUILD_KERNEL} \
        /usr/src/kernel-source-${BUILD_KERNEL} \
        /usr/src/linux-$(${BUILD_KERNEL} | sed 's/\([0-9]*\.[0-9]*\)\..*/\1/') \
        /usr/src/linux \
        /usr/src/kernels/${BUILD_KERNEL} \
        /usr/src/kernels

# prune the list down to only values that exist and have an include/linux
# sub-directory. We can't use include/config because some older kernels don't
# have this.
test_dir = $(shell [ -e ${dir}/include/linux ] && echo ${dir})
KSP := $(foreach dir, ${KSP}, ${test_dir})

# We will use this first valid entry in the search path, unless KSRC was set
# by the caller, in which case we assume a custom build and will skip depmod
# and initramfs update.
ifeq (,${KSRC})
  KSRC := $(firstword ${KSP})
else
  CUSTOM_BUILD := 1
endif

ifeq (,${KSRC})
  $(warning *** Kernel header files not in any of the expected locations.)
  $(warning *** Install the appropriate kernel development package, e.g.)
  $(error kernel-devel, for building kernel modules and try again)
endif

CHECK_AUX_BUS := $(realpath ./scripts/check_aux_bus)
$(shell chmod +x ${CHECK_AUX_BUS})

include common.mk

# SIOV support is only supported if the kernel has features for controlling
# PASID support. Do not even try to build SIOV support if the kernel lacks
# the necessary infrastructure.
ifneq ($(shell grep HAVE_PASID_SUPPORT $(src)/kcompat_generated_defs.h),)
export ENABLE_SIOV_SUPPORT := 1
else
# Force SIOV support on ARM, which is needed by ACC. Since we cannot
# distinguish between IMC and ACC, IMC may also include this code, but
# the users will not be able to use mdevs.
ifneq ($(findstring aarch64-intel-linux-,$(CC)),)
export ENABLE_SIOV_SUPPORT := 1
override CFLAGS_EXTRA += -DENABLE_ACC_PASID_WA
endif
endif # HAVE_PASID_SUPPORT is in kcompat_generated_defs.h
ifneq ($(shell grep HAVE_DEVLINK_PORT_NEW $(src)/kcompat_generated_defs.h),)
export ENABLE_DEVLINK_SUPPORT := 1
endif # HAVE_DEVLINK_PORT_NEW is in kcompat_generated_defs.h

# Construct CONFIG_<DRIVER>=m directives for all the targets. Define a
# 'to_upper' function to translate targets to uppercase.
to_upper = $(shell echo '$1' | tr '[:lower:]' '[:upper:]')
CONFIG_DRIVERS := $(strip $(addsuffix =m,$(addprefix CONFIG_,$(call to_upper,${TARGETS}))))

ifeq (${SPARSE_CHECK},YES)
  EXTRA_OPTS += C=2 W=1 CF="-D__CHECK_ENDIAN__"
endif

# Wrapper around kcompat's cmd_initrd, with checks for module signing.
ifeq (${CUSTOM_BUILD},1)
define cmd_initrd_check
@echo "Custom build detected. Skipping initramfs update."
endef
else ifeq (${cmd_initrd},)
define cmd_initrd_check
@echo "Unable to update initramfs. You may need to do this manually."
endef
else ifeq (${DISABLE_MODULE_SIGNING},Yes)
define cmd_initrd_check
@echo "Skipping initramfs update because idpf module cannot be signed."
endef
else
define cmd_initrd_check
@echo "Updating initramfs..."
$(call cmd_initrd)
endef
endif

#Wrapper around kcompat's cmd_depmod. In some build environments, depmod may not be present.
ifeq (${CUSTOM_BUILD},1)
define cmd_initrd_check
@echo "Custom build detected. Skipping depmod update."
endef
else ifeq (${cmd_depmod},)
define cmd_depmod_check
@echo "Unable to run depmod. You may need to do this manually."
endef
else ifeq (,$(wildcard /sbin/depmod))
define cmd_depmod_check
@echo "Unable to run depmod. You may need to do this manually."
endef
else
define cmd_depmod_check
@echo "Calling post install depmod..."
$(call cmd_depmod)
endef
endif

compile:
	@${MAKE} -C ${KSRC} M=$$PWD ${CONFIG_DRIVERS} ccflags-y="${CFLAGS_EXTRA} ${EXTRA_CFLAGS}" modules \
		NEED_AUX_BUS=${NEED_AUX_BUS} ${EXTRA_OPTS}

.PHONY: install
install: compile
	$(call kernelbuild,${CONFIG_DRIVERS},modules_install)
	$(call cmd_depmod_check)
	$(call cmd_initrd_check)

INSTALLED_MODS := $(strip $(addprefix ${INSTALL_MOD_PATH}/lib/modules/${KVER}/${INSTALL_MOD_DIR}/,${TARGETS}))
.PHONY: uninstall
uninstall:
	rm -rf ${INSTALLED_MODS}

.PHONY: clean
clean:
	@${MAKE} -C ${KSRC} M=$$PWD clean
	@rm -f kcompat_generated_defs.h

endif # ifneq (${KERNELRELEASE},)
endif # version target handling
