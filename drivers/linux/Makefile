# SPDX-License-Identifier: GPL-2.0
# SPDX-FileCopyrightText: Copyright (C) 2019-2024 Advanced Micro Devices, Inc.

IONIC_ETH_SRC = $(CURDIR)/eth/ionic
IONIC_RDMA_SRC = $(CURDIR)/rdma/drv/ionic

#KOPT += V=1		# verbose build
#KOPT += W=1		# extra warnings
#KOPT += C=1		# static analysis
#KOPT += CHECK=sparse	# static analysis tool
#KOPT += CHECK=scripts/coccicheck

default: all
ALL = modules

# Discover kernel and OpenFabrics configuration.
#
# Override kernel source path with
# `make KSRC=/path/to/your/sources` or
# `export KSRC=/path/to/your/sources`
#
# Override default OpenFabrics source path with
# `make OFA_KSRC=/path/to/your/sources` or
# `export OFA_KSRC=/path/to/your/sources`

KOPT = \
  CONFIG_IONIC=$(CONFIG_IONIC) \
  CONFIG_IONIC_MNIC=$(CONFIG_IONIC_MNIC) \
  CONFIG_MDEV=$(CONFIG_MDEV) \
  CONFIG_MNET_UIO_PDRV_GENIRQ=$(CONFIG_MNET_UIO_PDRV_GENIRQ) \
  CONFIG_INFINIBAND_IONIC=$(CONFIG_INFINIBAND_IONIC)
KCFLAGS += \
  $(CONFIG_IONIC:m=-DCONFIG_IONIC) \
  $(CONFIG_IONIC_MNIC:m=-DCONFIG_IONIC_MNIC) \
  $(CONFIG_MDEV:m=-DCONFIG_MDEV) \
  $(CONFIG_MNET_UIO_PDRV_GENIRQ:m=-DCONFIG_MNET_UIO_PDRV_GENIRQ) \
  $(CONFIG_INFINIBAND_IONIC:m=-DCONFIG_INFINIBAND_IONIC)
CONFIG_IONIC ?= m
CONFIG_INFINIBAND_IONIC ?= m

# Assume Pensando DSC context
ifeq ($(ARCH),aarch64)

  # Build system
  ifneq ($(MKINFRA),)
  # Ionic mnic and mdev for drivers ARM
    include ${MKINFRA}/config_${ARCH}.mk
    KSRC ?= ${NICDIR}/buildroot/output/${ASIC}/linux-headers
    KMOD_OUT_DIR ?= ${BLD_OUT_DIR}/drivers_submake
    KMOD_SRC_DIR ?= ${TOPDIR}/platform/drivers/linux-ionic
    export PATH := $(PATH):$(TOOLCHAIN_DIR)/bin
  endif
  ifeq ($(TOOLCHAIN_VERSION),11)
    KOPT += CROSS_COMPILE=aarch64-none-linux-gnu-
  else
    KOPT += CROSS_COMPILE=aarch64-linux-gnu-
  endif

  KOPT += ARCH=arm64

  CONFIG_IONIC_MNIC ?= m
  CONFIG_MDEV ?= m
  CONFIG_MNET_UIO_PDRV_GENIRQ ?= m

  DVER = $(shell cd $(KMOD_SRC_DIR) ; git describe --tags 2>/dev/null | tr - .)
  ifneq ($(DVER),)
    XX = $(shell echo $(DVER) > $(KMOD_SRC_DIR)/git_tag ; ls $(KMOD_SRC_DIR) )
    $(info b1 DVER $(DVER) XX $(XX) )
  else
    DVER = $(shell cat $(KMOD_SRC_DIR)/git_tag)
    $(info b2 DVER $(DVER) )
  endif

else

  # this host driver build assumes we're building in the linux-ionic directory
  # or from the drivers-linux-eth package ./drivers directory

  DVER = $(shell git describe --tags 2>/dev/null | tr - .)
  ifeq ($(DVER),)
    DVER = $(shell cat git_tag 2>/dev/null )
    $(info b3 DVER $(DVER) )
  endif

  # Ionic driver for host
  include linux_ver.mk

  KMOD_SRC_DIR ?= $(CURDIR)
  KMOD_OUT_DIR ?= $(CURDIR)
  KSRC ?= /lib/modules/$(shell uname -r)/build

  KCFLAGS += -Werror
  KCFLAGS += $(EXTRA_CFLAGS)

  KCFLAGS += -DIONIC_NOT_UPSTREAM

  ALL = eth

  # Ionic rdma driver, if present
  ifneq ($(wildcard $(IONIC_RDMA_SRC)),)
  ALL += rdma

    # Build for OFA rdma stack, if present
    OFA_KSRC ?= /usr/src/ofa_kernel/default
    ifneq ($(wildcard $(OFA_KSRC)),)
      ALL = rdma

      LINUXINCLUDE = -include $(OFA_KSRC)/include/generated/autoconf.h \
	       -include $$(srctree)/include/linux/kconfig.h \
	       -include $(OFA_KSRC)/include/linux/kconfig.h \
	       -include $(OFA_KSRC)/include/linux/compat-2.6.h \
	       -I$(OFA_KSRC)/include \
	       -I$(OFA_KSRC)/include/uapi \
	       -I$(OFA_KSRC)/drivers/infiniband/debug \
	       -I$$(srctree)/arch/$$(SRCARCH)/include \
	       -I$$(objtree)/arch/$$(SRCARCH)/include/generated \
	       -I$$(objtree)/include \
	       -I$$(srctree)/arch/$$(SRCARCH)/include/uapi \
	       -I$$(objtree)/arch/$$(SRCARCH)/include/generated/uapi \
	       -I$$(srctree)/include \
	       -I$$(srctree)/include/uapi \
	       -I$$(objtree)/include/generated/uapi \
	       $$(if $$(KBUILD_SRC), -I$$(objtree)/include2 -I$$(srctree)/include) \
	       -I$$(srctree)/arch/$$(SRCARCH)/include \
	       -I$$(objtree)/arch/$$(SRCARCH)/include/generated \

      OFA_KOPT += LINUXINCLUDE='$(LINUXINCLUDE)'
      OFA_KSYMS += $(OFA_KSRC)/Module.symvers

      # OFA does not provide semantic versioning for its kernel api.
      # Out-of-tree compatibility is based on hash in compat_version.
      OFA_HASH := $(shell cat '$(OFA_KSRC)/compat_version')
      OFA_KOPT += KCPPFLAGS="-DOFA_KERNEL=$(OFA_HASH)"
      # Relying on undefined macros evaluate to zero, do not warn.
      KCFLAGS += -Wno-undef
    endif
  endif
endif

# fallback
ifeq ($(DVER),)
  DVER = "25.04.5-003"
endif
KCFLAGS += -Ddrv_ver=\\\"$(DVER)\\\"

KOPT += KCFLAGS="$(KCFLAGS)" KBUILD_EXTRA_SYMBOLS="$(KSYMS)" LLVM=$(LLVM)

$(info linux_ver: BUILD_KERNEL ${BUILD_KERNEL} KVER ${KVER} LINUX_VERSION ${LINUX_VERSION} KSRC ${KSRC} KERNELRELEASE ${KERNELRELEASE} DVER ${DVER} )

ifneq	($(KMOD_SRC_DIR),$(KMOD_OUT_DIR))
  $(info Copying $(KMOD_SRC_DIR) to $(KMOD_OUT_DIR))
  $(shell cp -r "$(KMOD_SRC_DIR)"/* "$(KMOD_OUT_DIR)")
  KMOD_SRC_DIR = $(KMOD_OUT_DIR)
endif

# Run Kbuild. See ./Kbuild for CONFIG_* conditionals
define KBUILD_RULE
	cd $(KSRC) && . $(KMOD_SRC_DIR)/etc/kernel-gcc.sh && cd - && \
	$(MAKE) -C $(KSRC) M=$(KMOD_SRC_DIR) $(KOPT)
endef

all: $(ALL)

modules:
	$(KBUILD_RULE)

# Pensando DSC
mnic: CONFIG_IONIC_MNIC = m
mnic:
	@echo "===> Building driver: eth/ionic/ionic_mnic.ko"
	$(KBUILD_RULE)

Module.symvers.mnic: mnic
	cp Module.symvers $@

# Pensando DSC
mdev_rdma: Module.symvers.mnic
mdev_rdma: private KSYMS += $(CURDIR)/Module.symvers.mnic
mnic_rdma: CONFIG_INFINIBAND_IONIC = m
mnic_rdma:
	@echo "===> Built driver (conditional): rdma/drv/ionic/ionic_rdma.ko"
	$(KBUILD_RULE)

# Pensando DSC
mnet_uio_pdrv_genirq: CONFIG_MNET_UIO_PDRV_GENIRQ = m
mnet_uio_pdrv_genirq:
	@echo "===> Building driver: mnet_uio_pdrv_genirq/mnet_uio_pdrv_genirq.ko"
	$(KBUILD_RULE)

Module.symvers.uio: mnet_uio_pdrv_genirq
	cp Module.symvers $@

# Pensando DSC
mdev: Module.symvers.mnic Module.symvers.uio
mdev: private KSYMS += $(CURDIR)/Module.symvers.mnic $(CURDIR)/Module.symvers.uio
mdev: private CONFIG_IONIC =
mdev: private CONFIG_MDEV = m
mdev:
	@echo "===> Building driver: mdev/mdev.ko"
	$(KBUILD_RULE)

# Host
eth: private CONFIG_IONIC = m
eth: private CONFIG_INFINIBAND_IONIC =
eth:
	@echo "===> Building driver: eth/ionic/ionic.ko"
	$(KBUILD_RULE)

Module.symvers.eth: eth
	cp Module.symvers $@

modules.order.eth: eth
	cp modules.order $@
	[ -d .tmp_versions ] && cp -r .tmp_versions .tmp_versions.eth || true

ionic: eth

# The "private" makefile variables are not passed to prerequisite targets.
#
# The eth driver is required by the rdma driver, but we do not want to build the eth
# driver with OFA kernel opts.  Only apply the OFA kernel opts to the rdma driver.
#
# After, reinstate inputs for Kbuild to determine $(modules) during `make install`.

# Host
rdma: Module.symvers.eth modules.order.eth
rdma: private KSYMS += $(CURDIR)/Module.symvers.eth
rdma: private CONFIG_IONIC =
rdma: private CONFIG_INFINIBAND_IONIC = m
rdma: private KOPT += $(OFA_KOPT)
rdma: private KSYMS += $(OFA_KSYMS)
rdma:
	@[ -e "$(OFA_KSYMS)" ] && echo "===> Using OFA: $(OFA_KSRC)" || echo "===> Without OFA"
	@echo "===> Building driver (conditional): rdma/drv/ionic/ionic_rdma.ko"
	$(KBUILD_RULE)
	cat Module.symvers.eth >> Module.symvers
	cat modules.order.eth >> modules.order
	@[ -d .tmp_versions.eth ] && cp .tmp_versions.eth/* .tmp_versions/ || true

ionic_rdma: rdma

# Common
clean:
	$(KBUILD_RULE) clean
	rm -rf Module.symvers* modules.order* .tmp_versions*

INSTALL_MOD_DIR ?= updates
modules_install: KOPT += $(if $(DISABLE_MODULE_SIGNING),CONFIG_MODULE_SIG=n CONFIG_MODULE_SIG_ALL=)
modules_install: KOPT += INSTALL_MOD_DIR=$(INSTALL_MOD_DIR)
modules_install: KOPT += $(if $(DESTDIR),DEPMOD=true)
modules_install:
	@$(call warn_signed_modules)
	$(KBUILD_RULE) modules_install
	@[ -z "$(INSTALL_MOD_PATH)" ] && $(call cmd_depmod) || echo "Skipping depmod"

install: modules_install

cscope:
	find $(IONIC_ETH_SRC) $(IONIC_RDMA_SRC) -name '*.[ch]' > cscope.files
	cscope -bkq

FORCE:
.PHONY: default all mnic mnic_rdma mdev mnet_uio_pdrv_genirq eth rdma clean install modules_install cscope modules FORCE
