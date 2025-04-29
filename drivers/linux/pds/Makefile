KSRC ?= /lib/modules/$(shell uname -r)/build
CURDIR=$(shell pwd)

KCFLAGS="-I$(CURDIR)/include -DPDS_DRV_VER=\\\"1.116.0-10\\\""

ALL = pds_core pds_fwctl pds_vfio_pci pds_vdpa

define KBUILD_RULE
	cd $(KSRC) && . $(CURDIR)/../etc/kernel-gcc.sh && cd - && \
	$(MAKE) -C $(KSRC) KCFLAGS=$(KCFLAGS)
endef

all:	$(ALL)

pds_core:
	$(KBUILD_RULE) M=$(CURDIR)/core "CONFIG_PDS_CORE=m"

pds_vfio_pci: pds_core
	$(KBUILD_RULE) M=$(CURDIR)/vfio "CONFIG_PDS_VFIO_PCI=m" KBUILD_EXTRA_SYMBOLS=$(CURDIR)/core/Module.symvers

pds_vdpa: pds_core
	$(KBUILD_RULE) M=$(CURDIR)/vdpa "CONFIG_PDS_VDPA=m" KBUILD_EXTRA_SYMBOLS=$(CURDIR)/core/Module.symvers

pds_fwctl: pds_core
	$(KBUILD_RULE) M=$(CURDIR)/fwctl "CONFIG_FWCTL_PDS=m" KBUILD_EXTRA_SYMBOLS=$(CURDIR)/core/Module.symvers

clean_core:
	$(MAKE) -C $(KSRC) M=$(CURDIR)/core clean

clean_vdpa:
	$(MAKE) -C $(KSRC) M=$(CURDIR)/vdpa clean

clean_fwctl:
	$(MAKE) -C $(KSRC) M=$(CURDIR)/fwctl clean

clean_vfio:
	$(MAKE) -C $(KSRC) M=$(CURDIR)/vfio clean

clean: clean_core clean_vdpa clean_vfio

.PHONY: all pds_core pds_vfio_pci pds_vdpa pds_fwctl \
	clean clean_core clean_vdpa clean_vfio clean_fwctl
