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
IONIC_HAVE_XARRAY						symbol		xarray 							include/linux/xarray.h
IONIC_HAVE_IB_HW_STAT_DESC				symbol		rdma_stat_desc					include/rdma/ib_verbs.h
IONIC_HAVE_IB_UMEM_DMABUF_GET_PINNED	symbol		ib_umem_dmabuf_get_pinned		include/rdma/ib_umem.h
IONIC_HAVE_REQUIRED_IB_GID				symbol		ib_get_cached_gid				include/rdma/ib_cache.h
IONIC_HAVE_IB_UMEM_DMA_BLOCKS		symbol		ib_umem_num_dma_blocks			include/rdma/ib_umem.h
IONIC_HAVE_PEERMEM						symbol		ib_umem_get_peer				include/rdma/ib_umem.h
IONIC_HAVE_IB_GET_ETH_SPEED				symbol		ib_get_eth_speed				include/rdma/ib_verbs.h
IONIC_HAVE_RDMA_AH_ATTR_TYPE_ROCE		symbol		RDMA_AH_ATTR_TYPE_ROCE			include/rdma/ib_verbs.h
IONIC_HAVE_IB_MTU_INT_TO_ENUM			symbol		ib_mtu_int_to_enum				include/rdma/ib_verbs.h
IONIC_HAVE_EX_CMD_MODIFY_QP				symbol		IB_USER_VERBS_EX_CMD_MODIFY_QP	include/uapi/rdma/ib_user_verbs.h
IONIC_HAVE_RDMA_AH_ATTR					symbol		rdma_ah_attr					include/rdma/ib_verbs.h
IONIC_HAVE_RDMA_UDATA_DRV_CTX			symbol		rdma_udata_to_drv_context		include/rdma/uverbs_ioctl.h
IONIC_HAVE_ZALLOC_COHERENT				symbol		dma_zalloc_coherent				include/linux/dma-mapping.h
IONIC_HAVE_STATIC_ASSERT				symbol		static_assert					include/linux/build_bug.h
IONIC_HAVE_IB_DEV_NODE_DESC_MAX			symbol		IB_DEVICE_NODE_DESC_MAX			include/rdma/ib_verbs.h
IONIC_HAVE_CONFIGFS						symbol		configfs_register_subsystem		include/linux/configfs.h
IONIC_HAVE_CREATE_AH_UDATA_DMAC			nsymbol		ib_resolve_eth_dmac				include/rdma/ib_verbs.h
IONIC_HAVE_DYN_IBDEV_DBG				nsymbol		dynamic_ibdev_dbg				include/linux/dynamic_debug.h
IONIC_HAVE_CUSTOM_IB_SET_DEVICE_OPS		nsymbol		ib_device_ops					include/rdma/ib_verbs.h
IONIC_HAVE_IB_PORT_PHYS_STATE			nsymbol		ib_port_phys_state				include/rdma/ib_verbs.h
IONIC_HAVE_IBDEV_PRINT					nsymbol		ibdev_dbg						include/rdma/ib_verbs.h
IONIC_HAVE_IBDEV_PRINT_RATELIMITED		nsymbol		ibdev_warn_ratelimited			include/rdma/ib_verbs.h
IONIC_HAVE_AH_ATTR_CACHED_GID			nsymbol		ib_get_cached_gid				include/rdma/ib_cache.h
IONIC_HAVE_UNSIGNED_BITMAP_WEIGHT		symtype		bitmap_weight					include/linux/bitmap.h		unsigned int (const unsigned long *, unsigned int)
IONIC_HAVE_IB_UMEM_GET_IBDEV			symtype		ib_umem_get						include/rdma/ib_umem.h		struct ib_umem *(struct ib_device *, unsigned long, size_t, int)
IONIC_HAVE_IB_UMEM_GET_UDATA			symtype		ib_umem_get						include/rdma/ib_umem.h		struct ib_umem *(struct ib_udata *, unsigned long, size_t, int, int)
IONIC_HAVE_IB_UMEM_GET_NODMASYNC		symtype		ib_umem_get						include/rdma/ib_umem.h		struct ib_umem *(struct ib_udata *, unsigned long, size_t, int)
IONIC_HAVE_IB_UMEM_GET_OFA_UDATA		symtype		ib_umem_get						include/rdma/ib_umem.h		struct ib_umem *(struct ib_udata *, unsigned long, size_t, int, int, unsigned long)
IONIC_HAVE_IB_UMEM_GET_OFA				symtype		ib_umem_get						include/rdma/ib_umem.h		struct ib_umem *(struct ib_ucontext *, unsigned long, size_t, int, int, unsigned long)
IONIC_HAVE_IB_ALLOC_DEV_NO_CONTAINER	symtype		ib_alloc_device					include/rdma/ib_verbs.h		struct ib_device *(size_t )
IONIC_HAVE_IB_REGISTER_DEVICE_DMA		symtype		ib_register_device				include/rdma/ib_verbs.h		int (struct ib_device *, const char *, struct device *)
IONIC_HAVE_IB_REGISTER_DEVICE_NAME		symtype		ib_register_device				include/rdma/ib_verbs.h		int (struct ib_device *, const char *, int (*)(struct ib_device *, u8, struct kobject *))
IONIC_HAVE_IB_REGISTER_DEVICE_NAME_ONLY	symtype		ib_register_device				include/rdma/ib_verbs.h		int (struct ib_device *, const char *)
IONIC_HAVE_USER_MMAP_IO					symtype		rdma_user_mmap_io				include/rdma/ib_verbs.h		int (struct ib_ucontext *, struct vm_area_struct *, unsigned long, unsigned long, pgprot_t)
IONIC_HAVE_USER_MMAP_IO_WITH_ENTRY		symtype		rdma_user_mmap_io				include/rdma/ib_verbs.h		int (struct ib_ucontext *, struct vm_area_struct *, unsigned long, unsigned long, pgprot_t, struct rdma_user_mmap_entry *)
IONIC_HAVE_IB_MODIFY_QP_IS_OK_LINK_LAYER	symtype	ib_modify_qp_is_ok				include/rdma/ib_verbs.h		bool (enum ib_qp_state, enum ib_qp_state, enum ib_qp_type, enum ib_qp_attr_mask, enum rdma_link_laye)
IONIC_HAVE_QP_INIT_SRC_QPN				member		struct_ib_qp_init_attr	source_qpn			include/rdma/ib_verbs.h
IONIC_HAVE_QP_RATE_LIMIT				member		struct_ib_qp_attr		rate_limit			include/rdma/ib_verbs.h
IONIC_HAVE_IB_PD_FLAGS					member		struct_ib_pd			flags				include/rdma/ib_verbs.h
IONIC_HAVE_RDMA_DEV_OPS_EXT				member		struct_ib_device_ops	driver_id			include/rdma/ib_verbs.h
IONIC_HAVE_IB_UMEM_SG_TABLE				member		struct_ib_umem			sgt_append			include/rdma/ib_umem.h
IONIC_HAVE_IB_KERNEL_CAP_FLAGS			member		struct_ib_device_attr	kernel_cap_flags	include/rdma/ib_verbs.h
IONIC_HAVE_IB_HW_PORT_STATS				member		struct_ib_device_ops	alloc_hw_port_stats	include/rdma/ib_verbs.h
IONIC_HAVE_CREATE_USER_AH				member		struct_ib_device_ops	create_user_ah		include/rdma/ib_verbs.h
IONIC_HAVE_IB_ALLOC_CQ_OBJ				member		struct_ib_device_ops	size_ib_cq			include/rdma/ib_verbs.h
IONIC_HAVE_IBDEV_MAX_SEND_RECV_SGE		member		struct_ib_device_attr	max_send_sge		include/rdma/ib_verbs.h
IONIC_HAVE_RDMA_DRIVER_ID				member		struct_ib_device		driver_id			include/rdma/ib_verbs.h
IONIC_HAVE_IB_UVERBS_EX_CMD_MASK		member		struct_ib_device		uverbs_ex_cmd_mask	include/rdma/ib_verbs.h
IONIC_HAVE_IB_ALLOC_PD_OBJ				member		struct_ib_device_ops	size_ib_pd			include/rdma/ib_verbs.h
IONIC_HAVE_QP_RWQ_IND_TBL				member		struct_ib_qp_init_attr	rwq_ind_tbl			include/rdma/ib_verbs.h
IONIC_HAVE_DEV_GET_VECTOR_AFFINITY		member		struct_ib_device		get_vector_affinity	include/rdma/ib_verbs.h
IONIC_HAVE_DEVOP_GET_VECTOR_AFFINITY	member		struct_ib_device_ops	get_vector_affinity	include/rdma/ib_verbs.h
IONIC_HAVE_DEVOPS_DEVICE_GROUP		member		struct_ib_device_ops	device_group		include/rdma/ib_verbs.h
IONIC_HAVE_RDMA_SET_DEVICE_GROUP		symbol		rdma_set_device_sysfs_group		include/rdma/ib_verbs.h
IONIC_HAVE_DEV_GET_DEV_FW_STR			member		struct_ib_device		get_dev_fw_str		include/rdma/ib_verbs.h
IONIC_HAVE_DEVOP_GET_DEV_FW_STR			member		struct_ib_device_ops	get_dev_fw_str		include/rdma/ib_verbs.h
IONIC_HAVE_CONFIGFS_CONST			memtype		struct_config_item		ci_type		include/linux/configfs.h	const struct config_item_type *
IONIC_HAVE_CREATE_AH_INIT_ATTR		memtype		struct_ib_device_ops	create_ah	include/rdma/ib_verbs.h		int (*)(struct ib_ah *, struct rdma_ah_init_attr *, struct ib_udata *)
IONIC_HAVE_IB_ALLOC_AH_OBJ			memtype		struct_ib_device_ops	create_ah	include/rdma/ib_verbs.h		int (*)(struct ib_ah *, struct rdma_ah_attr *, u32, struct ib_udata *)
IONIC_HAVE_CREATE_AH_FLAGS			memtype		struct_ib_device_ops	create_ah	include/rdma/ib_verbs.h		struct ib_ah *(*)(struct ib_pd *, struct rdma_ah_attr *, u32, struct ib_udata *)
IONIC_HAVE_DEV_CREATE_AH_UDATA		memtype		struct_ib_device_ops	create_ah	include/rdma/ib_verbs.h		struct ib_ah *(*)(struct ib_pd *, struct ib_ah_attr *, struct ib_udata *)
IONIC_HAVE_DEVOP_CREATE_AH_UDATA	memtype		struct_ib_device_ops	create_ah	include/rdma/ib_verbs.h		struct ib_ah *(*)(struct ib_pd *, struct ib_ah_attr *, struct ib_udata *)
IONIC_HAVE_IB_ALLOC_QP_OBJ			memtype		struct_ib_device_ops	create_qp	include/rdma/ib_verbs.h		int (*)(struct ib_qp *, struct ib_qp_init_attr *, struct ib_udata *)
IONIC_HAVE_IB_DESTROY_CQ_VOID		memtype		struct_ib_device_ops	destroy_cq	include/rdma/ib_verbs.h		void (*)(struct ib_cq *, struct ib_udata *)
IONIC_HAVE_IB_DESTROY_AH_VOID		memtype		struct_ib_device_ops	destroy_ah	include/rdma/ib_verbs.h		void (*)(struct ib_ah *, u32)
IONIC_HAVE_DESTROY_AH_FLAGS			memtype		struct_ib_device_ops	destroy_ah	include/rdma/ib_verbs.h		int (*)(struct ib_ah *, u32)
IONIC_HAVE_IB_ALLOC_MR_UDATA		memtype		struct_ib_device_ops	alloc_mr	include/rdma/ib_verbs.h		struct ib_mr *(*)(struct ib_pd *, enum ib_mr_type, u32, struct ib_udata *)
IONIC_HAVE_IB_ALLOC_MW_OBJ			memtype		struct_ib_device_ops	alloc_mw	include/rdma/ib_verbs.h		int (*)(struct ib_mw *, struct ib_udata *)
IONIC_HAVE_IB_API_CREATE_CQ_ATTRS	memtype		struct_ib_device_ops	create_cq	include/rdma/ib_verbs.h		int (*)(struct ib_cq *, const struct ib_cq_init_attr *, struct uverbs_attr_bundle *)
IONIC_HAVE_IB_API_UDATA				memtype		struct_ib_device_ops	destroy_qp	include/rdma/ib_verbs.h 	int (*)(struct ib_qp *, struct ib_udata *)
IONIC_HAVE_IB_DEALLOC_PD_VOID		memtype		struct_ib_device_ops	dealloc_pd	include/rdma/ib_verbs.h 	void (*)(struct ib_pd *, struct ib_udata *)
IONIC_HAVE_IB_PORT_U32				memtype		struct_ib_device_ops	query_port	include/rdma/ib_verbs.h		int (*)(struct ib_device *, u32, struct ib_port_attr *)
IONIC_HAVE_IB_USER_MR_INIT_ATTR		memtype		struct_ib_device_ops	reg_user_mr	include/rdma/ib_verbs.h		struct ib_mr *(*)(struct ib_pd *, struct ib_mr_init_attr *, struct ib_udata *)
IONIC_HAVE_DEV_IB_GID_DEV_PORT_ID	memtype		struct_ib_device		add_gid		include/rdma/ib_verbs.h		int (*)(struct ib_device *, u8, unsigned int, const union ib_gid *, const struct ib_gid_attr *, void **)
IONIC_HAVE_DEVOP_IB_GID_DEV_PORT_ID	memtype		struct_ib_device_ops	add_gid		include/rdma/ib_verbs.h		int (*)(struct ib_device *, u8, unsigned int, const union ib_gid *, const struct ib_gid_attr *, void **)
IONIC_HAVE_DEV_CONST_IB_WR			memtype		struct_ib_device		post_send	include/rdma/ib_verbs.h		int (*)(struct ib_qp *, const struct ib_send_wr *, const struct ib_send_wr **)
IONIC_HAVE_DEVOP_CONST_IB_WR		memtype		struct_ib_device_ops	post_send	include/rdma/ib_verbs.h		int (*)(struct ib_qp *, const struct ib_send_wr *, const struct ib_send_wr **)
IONIC_HAVE_DEV_GET_DEV_FW_STR_LEN	memtype		struct_ib_device		get_dev_fw_str		include/rdma/ib_verbs.h		void (*)(struct ib_device *, char *, size_t)
IONIC_HAVE_DEVOP_GET_DEV_FW_STR_LEN	memtype		struct_ib_device_ops	get_dev_fw_str		include/rdma/ib_verbs.h		void (*)(struct ib_device *, char *, size_t)
IONIC_HAVE_IB_ALLOC_UCTX_OBJ		memtype		struct_ib_device_ops	alloc_ucontext		include/rdma/ib_verbs.h		int (*)(struct ib_ucontext *, struct ib_udata *)
IONIC_HAVE_IB_DEALLOC_UCTX_VOID		memtype		struct_ib_device_ops	dealloc_ucontext	include/rdma/ib_verbs.h		void (*)(struct ib_ucontext *)
IONIC_HAVE_IB_REREG_USER_MR_SWAP	memtype		struct_ib_device_ops	rereg_user_mr		include/rdma/ib_verbs.h		struct ib_mr *(*)(struct ib_mr *, int, u64, u64, u64, int, struct ib_pd *, struct ib_udata *)
IONIC_HAVE_IB_REG_MR_WITH_UATTRS	memtype		struct_ib_device_ops	reg_user_mr_dmabuf	include/rdma/ib_verbs.h		struct ib_mr *(*)(struct ib_pd *, u64, u64, u64, int, int, struct uverbs_attr_bundle *)
IONIC_HAVE_PORT_ATTR_IP_GIDS		member		struct_ib_port_attr	ip_gids			include/rdma/ib_verbs.h
IONIC_HAVE_NETDEV_MAX_MTU		member		struct_net_device	max_mtu			include/linux/netdevice.h
IONIC_HAVE_RDMA_GET_UDP_SPORT		symbol		rdma_get_udp_sport			include/rdma/ib_verbs.h
IONIC_HAVE_COUNTER_BIND_PORT		memtype		struct_ib_device_ops	counter_bind_qp		include/rdma/ib_verbs.h		int (*)(struct rdma_counter *counter, struct ib_qp *qp, u32 port)
" | egrep -v -e '^#' -e '^$' | sed 's/[ \t][ \t]*/:/g'
}

TOPDIR=$(dirname "$0")/../../..
source $TOPDIR/etc/kernel_compat_funcs.sh
