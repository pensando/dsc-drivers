# SPDX-License-Identifier: GPL-2.0
# Copyright(c) 2022 Pensando Systems, Inc

obj-$(CONFIG_PDS_CORE) := pds_core.o

ccflags-y := -g
subdir-ccflags-y += -I$(src)/include
subdir-ccflags-y += -I$(src)/../../../common


pds_core-y := main.o \
	      devlink.o \
	      auxbus.o \
	      dev.o \
	      adminq.o \
	      core.o \
	      netdev.o \
	      fw.o

pds_core-$(CONFIG_DEBUG_FS) += debugfs.o

