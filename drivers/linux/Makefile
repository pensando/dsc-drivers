ifneq ($(KERNELRELEASE),)
obj-$(CONFIG_IONIC) += eth/ionic/
obj-$(CONFIG_IONIC_MNIC) += eth/ionic/
obj-$(CONFIG_MDEV) += mdev/
obj-$(CONFIG_MNET_UIO_PDRV_GENIRQ) += mnet_uio_pdrv_genirq/
obj-$(CONFIG_INFINIBAND_IONIC) += rdma/drv/ionic/
else

IONIC_ETH_SRC = $(CURDIR)/eth/ionic
IONIC_RDMA_SRC = $(CURDIR)/rdma/drv/ionic

#KOPT += V=1		# verbose build
#KOPT += W=1		# extra warnings
#KOPT += C=1		# static analysis
#KOPT += CHECK=sparse	# static analysis tool
#KOPT += CHECK=scripts/coccicheck

ETH_KOPT += CONFIG_INFINIBAND_IONIC=_
RDMA_KOPT += CONFIG_INFINIBAND_IONIC=m
RDMA_KOPT += CONFIG_IONIC=_

default: all

# Discover kernel and open fabrics configuration.
#
# Override running kernel with
# `make KSRC=/path/to/your/sources` or
# `export KSRC=/path/to/your/sources`
#
# Override default open fabrics with
# `make OFA_KSRC=/path/to/your/sources` or
# `export OFA_KSRC=/path/to/your/sources`

ifeq ($(ARCH),aarch64)

# Ionic mnic and mdev for drivers ARM
include ${MKINFRA}/config_${ARCH}.mk
KSRC ?= ${NICDIR}/buildroot/output/${ASIC}/linux-headers
KMOD_OUT_DIR ?= ${BLD_OUT_DIR}/drivers_submake
KMOD_SRC_DIR ?= ${TOPDIR}/platform/drivers/linux-ionic
ETH_KOPT += CONFIG_IONIC_MNIC=m
ETH_KOPT += CONFIG_MDEV=m
ETH_KOPT += CONFIG_MNET_UIO_PDRV_GENIRQ=m
ifeq ($(TOOLCHAIN_VERSION),11)
KOPT += CROSS_COMPILE=aarch64-none-linux-gnu-
else
KOPT += CROSS_COMPILE=aarch64-linux-gnu-
endif
KOPT += ARCH=arm64
KCFLAGS += -DCONFIG_IONIC_MNIC
KCFLAGS += -DCONFIG_MDEV
KCFLAGS += -DCONFIG_MNET_UIO_PDRV_GENIRQ
ALL = mnic
ALL += mnic_rdma
ALL += mnet_uio_pdrv_genirq
ALL += mdev
export PATH := $(PATH):$(TOOLCHAIN_DIR)/bin

KSYMS_MNIC = $(KMOD_OUT_DIR)/Module.symvers.mnic
KSYMS_UIO = $(KMOD_OUT_DIR)/Module.symvers.uio

DVER = $(shell cd $(KMOD_SRC_DIR) ; git describe --tags 2>/dev/null)
ifneq ($(DVER),)
    XX = $(shell echo $(DVER) > $(KMOD_SRC_DIR)/git_tag ; ls $(KMOD_SRC_DIR) )
else
    DVER = $(shell cat $(KMOD_SRC_DIR)/git_tag)
endif

else

# this host driver build assumes we're building in the linux-ionic directory
# or from the drivers-linux-eth package ./drivers directory

DVER = $(shell git describe --tags 2>/dev/null)
ifeq ($(DVER),)
    DVER = $(shell cat git_tag 2>/dev/null )
endif

# Ionic driver for host
include linux_ver.mk

KSRC ?= /lib/modules/$(shell uname -r)/build
ETH_KOPT += CONFIG_IONIC=m
ETH_KOPT += CONFIG_IONIC_MNIC=_
ETH_KOPT += CONFIG_MDEV=_
ETH_KOPT += CONFIG_MNET_UIO_PDRV_GENIRQ=_
KCFLAGS += -DCONFIG_IONIC

KCFLAGS = -Werror
KCFLAGS += $(EXTRA_CFLAGS)


ALL = eth

# Ionic rdma driver, if present
ifneq ($(wildcard $(IONIC_RDMA_SRC)),)
ALL += rdma

# Build for OFA rdma stack, if present
OFA_KSRC ?= /usr/src/ofa_kernel/default
ifneq ($(wildcard $(OFA_KSRC)),)

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
    DVER = "25.02.1-001"
endif
KCFLAGS += -Ddrv_ver=\\\"$(DVER)\\\"

KOPT += KCFLAGS="$(KCFLAGS)" KBUILD_EXTRA_SYMBOLS="$(KSYMS)" LLVM=$(LLVM)

$(info linux_ver: BUILD_KERNEL ${BUILD_KERNEL} KVER ${KVER} LINUX_VERSION ${LINUX_VERSION} KSRC ${KSRC} KERNELRELEASE ${KERNELRELEASE} DVER ${DVER} )

all: $(ALL)

KBUILD_RULE = $(MAKE) -C $(KSRC) $(KOPT) M=$(CURDIR) KMOD_SRC_DIR=$(CURDIR)

mnic: KOPT+=$(ETH_KOPT)
mnic:
	@echo "===> Building MNIC driver "
	mkdir -p $(KMOD_OUT_DIR)
	touch $(KMOD_OUT_DIR)/Makefile
	$(MAKE) -C $(KSRC) V=1 M=$(KMOD_OUT_DIR) src=$(KMOD_SRC_DIR)/eth/ionic $(KOPT)
	mv ${KMOD_OUT_DIR}/Module.symvers ${KMOD_OUT_DIR}/Module.symvers.mnic



mnic_rdma: mnic
mnic_rdma: KOPT+=$(RDMA_KOPT)
mnic_rdma: KSYMS+=$(KSYMS_MNIC)
mnic_rdma:
	@echo "===> Building MNIC RDMA driver "
	$(MAKE) -C $(KSRC) M=$(KMOD_OUT_DIR) KMOD_SRC_DIR=$(KMOD_SRC_DIR) src=$(KMOD_SRC_DIR)/rdma/drv/ionic $(KOPT)

mnet_uio_pdrv_genirq: KOPT+=$(ETH_KOPT)
mnet_uio_pdrv_genirq:
	@echo "===> Building MNET_UIO driver "
	$(MAKE) -C $(KSRC) V=1 M=$(KMOD_OUT_DIR) src=$(KMOD_SRC_DIR)/mnet_uio_pdrv_genirq $(KOPT)
	mv ${KMOD_OUT_DIR}/Module.symvers ${KMOD_OUT_DIR}/Module.symvers.uio

mdev: KOPT+=$(ETH_KOPT)
mdev: KSYMS+=$(KSYMS_MNIC)
mdev: KSYMS+=$(KSYMS_UIO)
mdev:
	@echo "===> Building MDEV driver "
	$(MAKE) -C $(KSRC) V=1 M=$(KMOD_OUT_DIR) src=$(KMOD_SRC_DIR)/mdev $(KOPT)

eth: KOPT+=$(ETH_KOPT)
eth:
	@echo "===> Building ETH driver "
	+$(KBUILD_RULE)
	mv $(CURDIR)/Module.symvers $(CURDIR)/Module.symvers.ionic

# The "private" makefile variables are not passed to prerequisite targets.
#
# The eth driver is required by the rdma driver, but we do not want to build the eth
# driver with OFA kernel opts.  Only apply the OFA kernel opts to the rdma driver.

rdma: eth
rdma: private KOPT+=$(OFA_KOPT)
rdma: private KOPT+=$(RDMA_KOPT)
rdma: private KSYMS+=$(OFA_KSYMS)
rdma: private KSYMS+=$(CURDIR)/Module.symvers.ionic
rdma:
	@echo "===> Building RDMA driver "
	+$(KBUILD_RULE)
	mv $(CURDIR)/Module.symvers $(CURDIR)/Module.symvers.ionic_rdma || true

clean: KOPT+=$(ETH_KOPT)
clean:
	$(KBUILD_RULE) clean
	rm -f $(CURDIR)/Module.symvers*
	rm -f $(IONIC_RDMA_SRC)/autocompat.h $(IONIC_ETH_SRC)/autocompat.h

KBUILD_INSTALL_RULE = $(MAKE) -C $(KSRC) $(KOPT) \
		      $(if ${DISABLE_MODULE_SIGNING},CONFIG_MODULE_SIG=n) \
		      $(if ${DISABLE_MODULE_SIGNING},CONFIG_MODULE_SIG_ALL=) \
		      INSTALL_MOD_DIR=updates \
		      M=$(CURDIR)

install: modules_install
modules_install: KOPT+=$(ETH_KOPT)
modules_install: KOPT+=$(RDMA_KOPT)
modules_install:
	@$(call warn_signed_modules)
	$(KBUILD_INSTALL_RULE) modules_install
	$(call cmd_depmod)

cscope:
	find $(IONIC_ETH_SRC) $(IONIC_RDMA_SRC) -name '*.[ch]' > cscope.files
	cscope -bkq

.PHONY: default all mnic mnic_rdma mdev mnet_uio_pdrv_genirq eth rdma clean install modules_install cscope

endif
