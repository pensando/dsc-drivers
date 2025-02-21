#!/bin/bash

#
# Copyright(C) Advanced Micro Devices, Inc. All rights reserved.
#
# You may not use this software and documentation (if any) (collectively,
# the "Materials") except in compliance with the terms and conditions of
# the Software License Agreement included with the Materials or otherwise as
# set forth in writing and signed by you and an authorized signatory of AMD.
# If you do not have a copy of the Software License Agreement, contact your
# AMD representative for a copy.
#
# You agree that you will not reverse engineer or decompile the Materials,
# in whole or in part, except as allowed by applicable law.
#
# THE MATERIALS ARE DISTRIBUTED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OR
# REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
#


#
# prep-kernel-layout.sh <target-dir>
#
# Assumptions:
#    running in top of dsc-drivers directory
#
# Example Usage:
#    start in the top level of the dsc-drivers
#    create a target directory, such as ../tmp
#	$ mkdir ../tmp
#    run the script
#	$ prep-kernel-layout.sh ../tmp
#    overlay onto existing kernel
#	$ cp -a ../tmp/* ~/Work/mykernel/
#    test compile the drivers
#	$ cd ~/Work/mykernel
#	$ make M=`pwd`/drivers/net/ethernet/pensando/ionic KBUILD_MODPOST_WARN=1 modules
#	$ make M=`pwd`/drivers/infiniband/hw/ionic KBUILD_MODPOST_WARN=1 CONFIG_INFINIBAND_IONIC=m modules
#	$ make M=`pwd`/drivers/net/ethernet/amd/pds_core KBUILD_MODPOST_WARN=1 modules
#	$ make M=`pwd`/drivers/fwctl/pds KBUILD_MODPOST_WARN=1 CONFIG_FWCTL_PDS=m modules
#
#

#set -x

PROG=$0
top_dir=`pwd`

target_dir="$1"
if [[ ! -d $target_dir ]] ; then
	echo "Usage: $PROG <target-dir>"
	exit 1
fi


prep_files() {
	top_dir=$1
	target_dir=$2

	# Get ionic version string
	VER=`grep ' DVER = "' drivers/linux/Makefile | cut '-d"' -f2`

	# gather ionic eth files
	eth_src=drivers/linux/eth/ionic
	eth_dir=$target_dir/drivers/net/ethernet/pensando/ionic
	echo $eth_dir
	mkdir -p $eth_dir
	cp -a $eth_src/* $eth_dir
	cp -a $eth_src/../../linux_ver.mk $eth_dir
	cp -a $eth_src/../../etc/Makefile.common $eth_dir
	sed -i "s/^\\(#define IONIC_DRV_VERSION\\s\\+\\).*\$/\1\\\"$VER\\\"/" $eth_dir/ionic.h

	# fix up the eth autocompat stuff
	sed -i '4 a include $M/linux_ver.mk'       $eth_dir/Makefile
	sed -i '/CONFIG_IONIC_MNIC/d'              $eth_dir/Makefile
	sed -i 's/obj-.*ionic.o/obj-m := ionic.o/' $eth_dir/Makefile
	sed -i '/ccflags-y/s/$/ $(EXTRA_CFLAGS)/'  $eth_dir/Makefile

	sed -i 's/include .*Makefile.common/include $(src)\/Makefile.common/' $eth_dir/Makefile
	sed -i '/TOPDIR/d'                         $eth_dir/Makefile

	sed -i '/TOPDIR/d'                         $eth_dir/kernel_compat.sh
	sed -i 's/ $(TOPDIR)\/etc\/kernel_compat_funcs.sh//' $eth_dir/Makefile.common
	cat $eth_src/../../etc/kernel_compat_funcs.sh >> $eth_dir/kernel_compat.sh


	# gather ionic_rdma files
	rdma_src=drivers/linux/rdma/drv/ionic
	rdma_dir=$target_dir/drivers/infiniband/hw/ionic
	echo $rdma_dir
	mkdir -p $rdma_dir
	cp -a $rdma_src/* $rdma_dir

	mkdir -p $target_dir/include/uapi/rdma
	mv $rdma_dir/uapi/rdma/ionic-abi.h $target_dir/include/uapi/rdma
	rm -rf $rdma_dir/uapi/rdma/

	cp -a $rdma_src/../../../etc/Makefile.common $rdma_dir
        sed -i "s/^\\(#define IONIC_DRV_VERSION\\s\\+\\).*\$/\1\\\"$VER\\\"/" $rdma_dir/ionic_ibdev.c

	sed -i 's/include .*Makefile.common/include $(src)\/Makefile.common/' $rdma_dir/Makefile
	sed -i 's/^\(ccflags-y .*KMOD\)/# \1/'     $rdma_dir/Makefile
	sed -i 's/^# \(ccflags-y .*srctree\)/\1/'  $rdma_dir/Makefile
	sed -i '/TOPDIR/d'                         $rdma_dir/Makefile

	sed -i '/TOPDIR/d'                         $rdma_dir/kernel_compat.sh
	sed -i 's/ $(TOPDIR)\/etc\/kernel_compat_funcs.sh//' $rdma_dir/Makefile.common
	cat $rdma_src/../../../etc/kernel_compat_funcs.sh >> $rdma_dir/kernel_compat.sh


	# gather pds_core files
	pds_src=drivers/linux/pds
	core_dir=$target_dir/drivers/net/ethernet/amd/pds_core
	echo $core_dir
	mkdir -p $core_dir
	cp -a $pds_src/core/* $core_dir

	fwctl_dir=$target_dir/drivers/fwctl/pds
	echo $fwctl_dir
	mkdir -p $fwctl_dir
	cp -a $pds_src/fwctl/* $fwctl_dir
	unifdef -DUPSTREAM $pds_src/fwctl/main.c > $fwctl_dir/main.c
	mkdir -p $target_dir/include/uapi/fwctl
	cp $pds_src/include/linux/pds/uapi/fwctl/*.h $target_dir/include/uapi/fwctl

	pinc_dir=$target_dir/include/linux/pds
	echo $pinc_dir
	mkdir -p $pinc_dir
	cp -a $pds_src/include/linux/pds/*.h $pinc_dir
}

prep_files drivers/linux $target_dir

exit 0
