# SPDX-License-Identifier: GPL-2.0-only
# Copyright(c) 2022 Pensando Systems, Inc

obj-$(CONFIG_PDS_VDPA) := pds_vdpa.o

ccflags-y := -g -I$(src)
subdir-ccflags-y += -I$(src)/../../../common

pds_vdpa-y := aux_drv.o	\
	      cmds.o	\
	      pci_drv.o	\
	      debugfs.o \
	      virtio_pci.o \
	      vdpa_dev.o

