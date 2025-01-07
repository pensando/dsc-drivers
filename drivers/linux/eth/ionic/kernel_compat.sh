#!/bin/bash -eu
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2023-2024, Advanced Micro Devices, Inc.
#

me=$(basename "$0")

######################################################################
# Symbol definition map

function generate_kompat_symbols() {
    echo "
IONIC_HAVE_TCP_ALL_HEADERS			symbol		skb_tcp_all_headers		include/linux/tcp.h
IONIC_HAVE_INNER_TCP_ALL_HEADERS		symbol		skb_inner_tcp_all_headers	include/linux/tcp.h
IONIC_HAVE_DEVLINK_DRIVER_NAME_PUT		symbol		devlink_info_driver_name_put	include/net/devlink.h
IONIC_HAVE_SET_NETDEV_DEVLINK_PORT		symbol		SET_NETDEV_DEVLINK_PORT		include/linux/netdevice.h
IONIC_HAVE_DEVLINK_PARAMS_PUBLISH		symtype		devlink_params_publish		include/net/devlink.h		void(struct devlink *)
IONIC_HAVE_DEVLINK_ALLOC_DEV			symtype		devlink_alloc			include/net/devlink.h   struct devlink *(const struct devlink_ops *, size_t, struct device *)
IONIC_HAVE_VOID_DEVLINK_REGISTER		symtype		devlink_register		include/net/devlink.h   void(struct devlink *)
IONIC_HAVE_DEVLINK_REGISTER_WITH_DEV		symtype		devlink_register		include/net/devlink.h   int(struct devlink *, struct device *)
IONIC_HAVE_NET_DIM_SAMPLE_PTR			symtype		net_dim				include/linux/dim.h	void(struct dim *dim, const struct dim_sample *end_sample)
IONIC_HAVE_ETHTOOL_COALESCE_CQE			memtype		struct_ethtool_ops		get_coalesce	include/linux/ethtool.h int (*)(struct net_device *, struct ethtool_coalesce *, struct kernel_ethtool_coalesce *, struct netlink_ext_ack *)
IONIC_HAVE_ETHTOOL_SET_RINGPARAM_EXTACK		memtype		struct_ethtool_ops		set_ringparam	include/linux/ethtool.h int (*)(struct net_device *, struct ethtool_ringparam *, struct kernel_ethtool_ringparam *, struct netlink_ext_ack *)
" | egrep -v -e '^#' -e '^$' | sed 's/[ \t][ \t]*/:/g'
}

TOPDIR=$(dirname "$0")/../..
source $TOPDIR/etc/kernel_compat_funcs.sh
