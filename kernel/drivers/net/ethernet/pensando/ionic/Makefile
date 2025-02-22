# SPDX-License-Identifier: GPL-2.0
# Copyright(c) 2017 - 2019 Pensando Systems, Inc

IONIC_ETH_SRC = $(PWD)/eth/ionic
include $M/linux_ver.mk

obj-m := ionic.o

ccflags-y := -g -I$(src) $(EXTRA_CFLAGS)

ionic-y := ionic_main.o ionic_bus_pci.o ionic_dev.o ionic_ethtool.o \
	   ionic_lif.o ionic_rx_filter.o ionic_txrx.o ionic_debugfs.o \
	   ionic_api.o ionic_stats.o ionic_devlink.o kcompat.o ionic_fw.o \
	   dim.o net_dim.o
ifdef CONFIG_AUXILIARY_BUS
ionic-y += ionic_aux.o
endif

ionic-$(CONFIG_PTP_1588_CLOCK) += ionic_phc.o
ionic-$(CONFIG_SYSFS) += ionic_sysfs.o

ionic_mnic-y := ionic_main.o ionic_bus_platform.o ionic_dev.o ionic_ethtool.o \
	        ionic_lif.o ionic_rx_filter.o ionic_txrx.o ionic_debugfs.o \
	        ionic_api.o ionic_stats.o ionic_devlink.o kcompat.o ionic_fw.o \
		dim.o net_dim.o
ionic_mnic-$(CONFIG_PTP_1588_CLOCK) += ionic_phc.o
ifeq ($(KVER),5.10.28-1)
ionic_mnic-$(CONFIG_PTP_1588_CLOCK) += ionic_phc_weak.o
endif
ionic_mnic-$(CONFIG_SYSFS) += ionic_sysfs.o
ifdef CONFIG_AUXILIARY_BUS
ionic_mnic-y += ionic_aux.o
endif

ifdef KERNELRELEASE
IONIC_AUTOCOMPAT := $(src)/autocompat.h

include $(src)/Makefile.common
$(addprefix $(obj)/,$(ionic-y)): $(IONIC_AUTOCOMPAT)
$(addprefix $(obj)/,$(ionic_mnic-y)): $(IONIC_AUTOCOMPAT)
$(obj)/ionic_sysfs.o: $(IONIC_AUTOCOMPAT)
$(obj)/ionic_phc.o: $(IONIC_AUTOCOMPAT)
$(obj)/ionic_phc_weak.o: $(IONIC_AUTOCOMPAT)
endif
