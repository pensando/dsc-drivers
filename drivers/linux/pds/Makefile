KSRC ?= /lib/modules/$(shell uname -r)/build
CURDIR=$(shell pwd)

ALL = pds_core pds_vfio pds_vdpa
all:	$(ALL)

pds_core:
	$(MAKE) -C $(KSRC) M=$(CURDIR)/core "CONFIG_PDS_CORE=m"

pds_vfio:
	$(MAKE) -C $(KSRC) M=$(CURDIR)/vfio "CONFIG_PDS_VFIO=m"

pds_vdpa:
	$(MAKE) -C $(KSRC) M=$(CURDIR)/vdpa "CONFIG_PDS_VDPA=m"

clean:
	$(MAKE) -C $(KSRC) M=$(CURDIR)/core clean
	$(MAKE) -C $(KSRC) M=$(CURDIR)/vfio clean
	$(MAKE) -C $(KSRC) M=$(CURDIR)/vdpa clean

.PHONY: all pds_core pds_vfio pds_vdpa clean
