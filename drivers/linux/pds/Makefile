KSRC ?= /lib/modules/$(shell uname -r)/build
CURDIR=$(shell pwd)

KCFLAGS="-I$(CURDIR)/include"

ALL = pds_core pds_vfio_pci pds_vdpa
all:	$(ALL)

pds_core:
	$(MAKE) -C $(KSRC) KCFLAGS=$(KCFLAGS) M=$(CURDIR)/core "CONFIG_PDS_CORE=m"

pds_vfio_pci: pds_core
	$(MAKE) -C $(KSRC) KBUILD_EXTRA_SYMBOLS=$(CURDIR)/core/Module.symvers KCFLAGS=$(KCFLAGS) M=$(CURDIR)/vfio "CONFIG_PDS_VFIO_PCI=m"

pds_vdpa: pds_core
	$(MAKE) -C $(KSRC) KBUILD_EXTRA_SYMBOLS=$(CURDIR)/core/Module.symvers KCFLAGS=$(KCFLAGS) M=$(CURDIR)/vdpa "CONFIG_PDS_VDPA=m"

clean_core:
	$(MAKE) -C $(KSRC) M=$(CURDIR)/core clean

clean_vdpa:
	$(MAKE) -C $(KSRC) M=$(CURDIR)/vdpa clean
clean_vfio:
	$(MAKE) -C $(KSRC) M=$(CURDIR)/vfio clean

clean: clean_core clean_vdpa clean_vfio

.PHONY: all pds_core pds_vfio_pci pds_vdpa \
	clean clean_core clean_vdpa clean_vfio

