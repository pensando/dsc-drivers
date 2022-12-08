# SPDX-License-Identifier: GPL-2.0-only
# Copyright(c) 2022 Pensando Systems, Inc

obj-$(CONFIG_PDS_VFIO) := pds_vfio.o

ccflags-y := -g -I$(src)
subdir-ccflags-y += -I$(src)/../../../common

pds_vfio-y := aux_drv.o		\
	      cmds.o		\
	      dirty.o		\
	      lm.o		\
	      pci_drv.o		\
	      vfio_dev.o	\
	      trace.o
