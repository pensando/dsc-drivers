# SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB

ifeq ($(CONFIG_INFINIBAND),)
$(info ****** Skip building IONIC RDMA driver, CONFIG_INFINIBAND not set ******)
else ifeq ($(CONFIG_AUXILIARY_BUS),)
$(info ****** Skip building IONIC RDMA driver, CONFIG_AUXILIARY_BUS not set ******)
else
# internal version: $(KMOD_SRC_DIR) is abs path of drivers-linux/drivers
# ccflags-y := -I$(KMOD_SRC_DIR)/rdma/drv/ionic/uapi -I$(KMOD_SRC_DIR)/eth/ionic -I$(KMOD_SRC_DIR)/../common
# upstream version
ccflags-y :=  -I $(srctree)/drivers/net/ethernet/pensando/ionic


obj-$(CONFIG_INFINIBAND_IONIC)	+= ionic_rdma.o

ionic_rdma-y :=	\
	ionic_ibdev.o ionic_queue.o ionic_sysfs.o \
	ionic_controlpath.o ionic_datapath.o \
	ionic_admin.o ionic_pgtbl.o ionic_hw_stats.o \
	ionic_dcqcn.o ionic_res.o

ifdef KERNELRELEASE
export OFA_KSRC ?= /usr/src/ofa_kernel/default
include $(src)/Makefile.common
$(addprefix $(obj)/,$(ionic_rdma-y)): $(src)/autocompat.h
$(obj)/ionic_rdma.o: $(src)/autocompat.h
endif

endif
