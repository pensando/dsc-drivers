ifneq ($(KERNELRELEASE),)
obj-$(CONFIG_IONIC) += eth/ionic/
obj-$(CONFIG_IONIC_MNIC) += eth/ionic/
obj-$(CONFIG_MNET) += mnet/
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

default: all
ALL = eth

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

# Ionic mnic and mnet for drivers ARM
include ${MKINFRA}/config_${ARCH}.mk
KSRC ?= $(AARCH64_LINUX_HEADERS)
ETH_KOPT += CONFIG_IONIC_MNIC=m
ETH_KOPT += CONFIG_MNET=m
ETH_KOPT += CONFIG_MNET_UIO_PDRV_GENIRQ=m
ETH_KOPT += CROSS_COMPILE=aarch64-linux-gnu-
ETH_KOPT += ARCH=arm64
ALL += mnet
ALL += mnet_uio_pdrv_genirq
export PATH := $(PATH):$(TOOLCHAIN_DIR)/bin

else

# Ionic driver for host
KSRC ?= /lib/modules/$(shell uname -r)/build
ETH_KOPT += CONFIG_IONIC=m
ETH_KOPT += CONFIG_IONIC_MNIC=_
ETH_KOPT += CONFIG_MNET=_

KCFLAGS = -Werror

include linux_ver.mk
KCFLAGS += $(EXTRA_CFLAGS)

# Ionic rdma driver, if present
ifneq ($(wildcard $(IONIC_RDMA_SRC)),)
ALL += rdma

# Build for OFA rdma stack, if present
OFA_KSRC ?= /usr/src/ofa_kernel/default
ifneq ($(wildcard $(OFA_KSRC)),)
LINUXINCLUDE = $$(UBUNTUINCLUDE) \
	       -I$(OFA_KSRC)/include \
	       -I$$(srctree)/arch/$$(SRCARCH)/include \
	       -I$$(objtree)/arch/$$(SRCARCH)/include/generated \
	       $$(if $$(KBUILD_SRC), -I$$(srctree)/include) \
	       -I$$(objtree)/include \
	       -I$(OFA_KSRC)/include/uapi \
	       -I$$(srctree)/arch/$$(SRCARCH)/include/uapi \
	       -I$$(objtree)/arch/$$(SRCARCH)/include/generated/uapi \
	       -I$$(srctree)/include/uapi \
	       -I$$(objtree)/include/generated/uapi \
	       -include $$(srctree)/include/linux/kconfig.h
OFA_KOPT += LINUXINCLUDE='$(LINUXINCLUDE)'
OFA_KOPT += KBUILD_EXTRA_SYMBOLS='$(OFA_KSRC)/Module.symvers'

# OFA does not provide semantic versioning for its kernel api.
# Out-of-tree compatibility is based on hash in compat_version.
OFA_HASH := $(shell cat '$(OFA_KSRC)/compat_version')
OFA_KOPT += KCPPFLAGS="-DOFA_KERNEL=$(OFA_HASH)"
# Relying on undefined macros evaluate to zero, do not warn.
KCFLAGS += -Wno-undef
endif
endif
endif

KOPT += KCFLAGS="$(KCFLAGS)"

all: $(ALL)

KBUILD_RULE = $(MAKE) -C $(KSRC) $(KOPT) M=$(CURDIR)
mnet: eth mnet_uio_pdrv_genirq
mnet: KOPT+=$(ETH_KOPT)
mnet:
	$(KBUILD_RULE)

mnet_uio_pdrv_genirq: KOPT+=$(ETH_KOPT)
mnet_uio_pdrv_genirq:
	$(KBUILD_RULE)


eth: KOPT+=$(ETH_KOPT)
eth:
	$(KBUILD_RULE)

rdma: eth
rdma: KOPT+=$(RDMA_KOPT)
rdma: KOPT+=$(OFA_KOPT)
rdma:
	$(KBUILD_RULE)

clean: KOPT+=$(ETH_KOPT)
clean:
	$(KBUILD_RULE) clean

install: modules_install
modules_install: KOPT+=$(ETH_KOPT)
modules_install: KOPT+=$(RDMA_KOPT)
modules_install:
	$(KBUILD_RULE) modules_install

cscope:
	find $(IONIC_ETH_SRC) $(IONIC_RDMA_SRC) -name '*.[ch]' > cscope.files
	cscope -bkq

.PHONY: default all eth rdma clean install modules_install cscope

endif
