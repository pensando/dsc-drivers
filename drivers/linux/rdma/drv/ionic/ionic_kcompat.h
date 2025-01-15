/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2018-2020 Pensando Systems, Inc.  All rights reserved.
 *
 * Thanks @Intel for some of the Ubuntu bits!
 */

#ifndef IONIC_KCOMPAT_H
#define IONIC_KCOMPAT_H

#include "autocompat.h"
#include <rdma/ib_verbs.h>

/****************************************************************************
 *
 * Compatibility for kernel-only features not affected by OFA version
 *
 */
#include <linux/version.h>
#include <linux/netdevice.h>
#if defined(OFA_KERNEL)
#include "ionic_kcompat_ofa.h"
#endif
#ifndef UTS_RELEASE
#include <generated/utsrelease.h>
#endif

/* Ubuntu Release ABI is the 4th digit of their kernel version. You can find
 * it in /usr/src/linux/$(uname -r)/include/generated/utsrelease.h for new
 * enough versions of Ubuntu. Otherwise you can simply see it in the output of
 * uname as the 4th digit of the kernel. The UTS_UBUNTU_RELEASE_ABI is not in
 * the linux-source package, but in the linux-headers package. It begins to
 * appear in later releases of 14.04 and 14.10.
 *
 * Ex:
 * <Ubuntu 14.04.1>
 *  $uname -r
 *  3.13.0-45-generic
 * ABI is 45
 *
 * <Ubuntu 14.10>
 *  $uname -r
 *  3.16.0-23-generic
 * ABI is 23
 *
 * Unfortunately, this isn't always true for mainline kernels that can be
 * installed for Ubuntu. For example installing v5.4.20
 * from https://kernel.ubuntu.com/~kernel-ppa/mainline/ will result in an
 * ABI version of 050420, which seems to be mirroring the version, i.e.
 * 05.04.20. If this is the case then the UTS_UBUNTU_RELEASE_ABI and how we
 * use it in kcompat may not be useful or correct.
 */
#ifndef UTS_UBUNTU_RELEASE_ABI
#define UBUNTU_VERSION_CODE 0
#else
#if UTS_UBUNTU_RELEASE_ABI > 65535
#error UTS_UBUNTU_RELEASE_ABI is too large...
#endif /* UTS_UBUNTU_RELEASE_ABI > 65535 */

/* Ubuntu does not provide actual release version macro, so we use the kernel
 * version plus the ABI to generate a unique version code specific to Ubuntu.
 * In addition, we mask the lower 8 bits of LINUX_VERSION_CODE in order to
 * ignore differences in sublevel which are not important since we have the
 * ABI value. Otherwise, it becomes impossible to correlate ABI to version for
 * ordering checks. We also shift the modified LINUX_VERSION_CODE by 8.
 *
 * This lets us store an ABI value up to 65535, since it can take the
 * space that would use the lower byte of the Linux version code and the free
 * byte from shifting the masked LINUX_VERSION_CODE.
 */
#define UBUNTU_VERSION_CODE (((~0xFF & LINUX_VERSION_CODE) << 8) + \
			     UTS_UBUNTU_RELEASE_ABI)

#if ( LINUX_VERSION_CODE <= KERNEL_VERSION(3,0,0) )
/* Our version code scheme does not make sense for non 3.x or newer kernels,
 * and we have no support in kcompat for this scenario. Thus, treat this as a
 * non-Ubuntu kernel. Possibly might be better to error here.
 */
#define UTS_UBUNTU_RELEASE_ABI 0
#define UBUNTU_VERSION_CODE 0
#endif

#endif

/* We ignore the 3rd digit since we want to give precedence to the additional
 * ABI value provided by Ubuntu. Also, we keep the 3rd digit so it's in the same
 * format as the LINUX_KERNEL_VERSION macro.
 */
#define UBUNTU_VERSION(a, b, c, d) (((a) << 24) + ((b) << 16) + (d))

#define IONIC_KCOMPAT_UBUNTU_VERSION_AFTER(LX_MAJ, LX_MIN, UBUNTU_ABI) \
	(UBUNTU_VERSION_CODE && UBUNTU_VERSION_CODE > UBUNTU_VERSION(LX_MAJ, LX_MIN, 0, UBUNTU_ABI))

#if defined(RHEL_RELEASE_VERSION)
#define IONIC_KCOMPAT_KERN_VERSION_PRIOR_TO(LX_MAJ, LX_MIN, RH_MAJ, RH_MIN, UBUNTU_ABI) \
	(RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(RH_MAJ, RH_MIN))
#elif defined(UTS_UBUNTU_RELEASE_ABI)
#define IONIC_KCOMPAT_KERN_VERSION_PRIOR_TO(LX_MAJ, LX_MIN, RH_MAJ, RH_MIN, UBUNTU_ABI) \
	(UBUNTU_VERSION_CODE < UBUNTU_VERSION(LX_MAJ, LX_MIN, 0, UBUNTU_ABI))
#else
#define IONIC_KCOMPAT_KERN_VERSION_PRIOR_TO(LX_MAJ, LX_MIN, RH_MAJ, RH_MIN, UBUNTU_ABI) \
	(LINUX_VERSION_CODE < KERNEL_VERSION(LX_MAJ, LX_MIN, 0))
#endif

#if IONIC_KCOMPAT_KERN_VERSION_PRIOR_TO(/* Linux */ 3,11, /* RHEL */ 7,6, /* UBUNTU */ 0)
#define netdev_notifier_info_to_dev(ptr) (ptr)
#endif

#if defined(IONIC_HAVE_DEV_GET_VECTOR_AFFINITY) || defined(IONIC_HAVE_DEVOP_GET_VECTOR_AFFINITY)
#define IONIC_HAVE_GET_VECTOR_AFFINITY
#endif

#if IONIC_KCOMPAT_KERN_VERSION_PRIOR_TO(/* Linux */ 4,16, /* RHEL */ 7,7, /* UBUNTU */ 0)
/* The return value of the strscpy() and strlcpy() functions is different.
 * This could be potentially hazard for the future.
 * To avoid this the void result is forced.
 * So it is not possible use this function with the return value.
 * Return value is required in kernel 4.3 through 4.15.
 */
#define strscpy(...) ((void)(strlcpy(__VA_ARGS__)))
#endif

#if IONIC_KCOMPAT_KERN_VERSION_PRIOR_TO(/* Linux */ 4,17, /* RHEL */ 99,99, /* UBUNTU */ 0)
#elif IONIC_KCOMPAT_KERN_VERSION_PRIOR_TO(/* Linux */ 4,20, /* RHEL */ 99,99, /* UBUNTU */ 0)
/* 4.17, 4.18, 4.19: A radix_tree now includes a spinlock called xa_lock */
#define HAVE_RADIX_TREE_LOCK
#elif IONIC_KCOMPAT_KERN_VERSION_PRIOR_TO(/* Linux */ 5,0, /* RHEL */ 99,99, /* UBUNTU */ 0)
/* 4.20: xa_for_each() has extra arguments */
#ifndef HAVE_XARRAY_FOR_EACH_ARGS
#define HAVE_XARRAY_FOR_EACH_ARGS
#endif
#endif

#ifdef IONIC_HAVE_XARRAY
#ifdef HAVE_XARRAY_FOR_EACH_ARGS
#include <linux/xarray.h>
#undef xa_for_each
#define xa_for_each(xa, index, entry)					\
	for (entry = xa_find(xa, &index, ULONG_MAX, XA_PRESENT); entry;	\
	     entry = xa_find_after(xa, &index, ULONG_MAX, XA_PRESENT))
#endif /* HAVE_XARRAY_FOR_EACH_ARGS */
#else /* IONIC_HAVE_XARRAY */
/* Create an xarray from a radix_tree_root */
#include <linux/radix-tree.h>

#ifdef HAVE_RADIX_TREE_LOCK
#define xarray       radix_tree_root
#define xa_tree
#define xa_init_flags(_xa, _fl) INIT_RADIX_TREE((_xa), _fl)
#else
struct xarray {
	spinlock_t x_lock;
	struct radix_tree_root x_tree;
};
#define xa_tree(_xa) &(_xa)->x_tree
static inline void xa_init_flags(struct xarray *xa, gfp_t flags)
{
	spin_lock_init(&xa->x_lock);
	INIT_RADIX_TREE(xa_tree(xa), flags);
}

#define xa_lock(_xa) spin_lock(&(_xa)->x_lock)
#define xa_unlock(_xa) spin_unlock(&(_xa)->x_lock)
#endif /* HAVE_RADIX_TREE_LOCK */

#define xa_iter radix_tree_iter
#define xa_for_each_slot(_xa, _slot, _iter)				\
	radix_tree_for_each_slot((_slot), xa_tree(_xa), (_iter), 0)
#define xa_load(_xa, _idx) radix_tree_lookup(xa_tree(_xa), _idx)
#define xa_destroy(_xa)

static inline void *xa_store(struct xarray *xa, unsigned long idx,
			     void *item, gfp_t unused)
{
	int ret;

	xa_lock(xa);
	ret = radix_tree_insert(xa_tree(xa), idx, item);
	xa_unlock(xa);

	return (ret ? ERR_PTR(ret) : item);
}

static inline int xa_err(void *item)
{
	return (IS_ERR(item) ? PTR_ERR(item) : 0);
}

static inline void xa_erase(struct xarray *xa, unsigned long idx)
{
	xa_lock(xa);
	radix_tree_delete(xa_tree(xa), idx);
	xa_unlock(xa);
}
#endif /* IONIC_HAVE_XARRAY */
#ifndef IONIC_HAVE_STATIC_ASSERT

#define __static_assert(expr, msg, ...) _Static_assert(expr, msg)
#define static_assert(expr, ...) __static_assert(expr, ##__VA_ARGS__, #expr)
#endif

/****************************************************************************
 *
 * Compatibility for OFED features that may be affected by OFA version
 *
 */
#if defined(OFA_KERNEL)
#define IONIC_KCOMPAT_VERSION_PRIOR_TO(LX_MAJ, LX_MIN, RH_MAJ, RH_MIN, OFA) \
	OFA_COMPAT_CHECK(OFA_KERNEL, OFA)
#else
#define IONIC_KCOMPAT_VERSION_PRIOR_TO(LX_MAJ, LX_MIN, RH_MAJ, RH_MIN, OFA) \
	IONIC_KCOMPAT_KERN_VERSION_PRIOR_TO(LX_MAJ, LX_MIN, RH_MAJ, RH_MIN, /* UBUNTU */ 0)
#endif

#ifndef IONIC_HAVE_IB_DEV_NODE_DESC_MAX
#define IB_DEVICE_NODE_DESC_MAX sizeof(((struct ib_device *)0)->node_desc)
#endif

#if defined(IONIC_HAVE_DEV_CREATE_AH_UDATA) || defined(IONIC_HAVE_DEVOP_CREATE_AH_UDATA) \
		|| defined(IONIC_HAVE_CREATE_AH_FLAGS) || defined(IONIC_HAVE_CREATE_AH_INIT_ATTR)
#define IONIC_HAVE_CREATE_AH_UDATA
#endif

#if defined(IONIC_HAVE_DEV_GET_DEV_FW_STR) || defined(IONIC_HAVE_DEVOP_GET_DEV_FW_STR)
#define IONIC_HAVE_GET_DEV_FW_STR
#endif

#if IONIC_KCOMPAT_VERSION_PRIOR_TO(/* Linux */ 4,11, /* RHEL */ 7,5, /* OFA */ 4_11)
#define HAVE_REQUIRED_DMA_DEVICE
#endif

#if IONIC_KCOMPAT_VERSION_PRIOR_TO(/* Linux */ 4,14, /* RHEL */ 7,5, /* OFA */ 4_14b)
#define HAVE_MANDATORY_IB_MODIFY_PORT
#else /* 4.14.0 and later */
#endif

#if defined(IONIC_HAVE_DEV_GET_DEV_FW_STR_LEN) || defined(IONIC_HAVE_DEVOP_GET_DEV_FW_STR_LEN)
#define IONIC_HAVE_GET_DEV_FW_STR_LEN
#endif

#if defined(IONIC_HAVE_DEV_IB_GID_DEV_PORT_ID) || defined(IONIC_HAVE_DEVOP_IB_GID_DEV_PORT_ID)
#define IONIC_HAVE_IB_GID_DEV_PORT_INDEX
#endif

#if defined(IONIC_HAVE_RDMA_DRIVER_ID) || defined(IONIC_HAVE_RDMA_DEV_OPS_EXT)
#define RDMA_DRIVER_IONIC 242
#endif

#if defined(IONIC_HAVE_DEV_CONST_IB_WR) || defined(IONIC_HAVE_DEVOP_CONST_IB_WR)
#define IONIC_HAVE_CONST_IB_WR
#endif

#if IONIC_KCOMPAT_VERSION_PRIOR_TO(/* Linux */ 5,0, /* RHEL */ 99,99, /* OFA */ 5_0)
#define RDMA_CREATE_AH_SLEEPABLE 0
#endif

#ifndef IONIC_HAVE_UNSIGNED_BITMAP_WEIGHT
#define bitmap_weight(...) ((unsigned int)bitmap_weight(__VA_ARGS__))
#endif

#ifdef IONIC_HAVE_DYN_IBDEV_DBG
/* OFA 4.7 adds the ibdev print macros, but doesn't define this */
static inline void dynamic_ibdev_dbg(struct ib_device *___dev, ...) { }
#endif

#if defined(IONIC_HAVE_USER_MMAP_IO)
#define rdma_user_mmap_io(ibctx, vma, pfn, size, pgprot, ctx) \
	rdma_user_mmap_io(ibctx, vma, pfn, size, pgprot)
#elif !defined(IONIC_HAVE_USER_MMAP_IO_WITH_ENTRY)
#define rdma_user_mmap_io(ibctx, vma, pfn, size, pgprot, ctx) \
	io_remap_pfn_range(vma, (vma)->vm_start, pfn, size, pgprot)
#endif

#ifndef IONIC_HAVE_IB_MTU_INT_TO_ENUM
static inline enum ib_mtu ib_mtu_int_to_enum(int mtu)
{
	if (mtu >= 4096)
		return IB_MTU_4096;
	else if (mtu >= 2048)
		return IB_MTU_2048;
	else if (mtu >= 1024)
		return IB_MTU_1024;
	else if (mtu >= 512)
		return IB_MTU_512;
	else
		return IB_MTU_256;
}

#endif /* IONIC_HAVE_IB_MTU_INT_TO_ENUM */
#ifndef IONIC_HAVE_RDMA_AH_ATTR
#define rdma_ah_attr ib_ah_attr
#define rdma_ah_read_grh(attr) (&(attr)->grh)

static inline void rdma_ah_set_sl(struct rdma_ah_attr *attr, u8 sl)
{
	attr->sl = sl;
}

static inline void rdma_ah_set_port_num(struct rdma_ah_attr *attr, u8 port_num)
{
	attr->port_num = port_num;
}

static inline void rdma_ah_set_grh(struct rdma_ah_attr *attr,
				   union ib_gid *dgid, u32 flow_label,
				   u8 sgid_index, u8 hop_limit,
				   u8 traffic_class)
{
	struct ib_global_route *grh = rdma_ah_read_grh(attr);

	attr->ah_flags = IB_AH_GRH;
	if (dgid)
		grh->dgid = *dgid;
	grh->flow_label = flow_label;
	grh->sgid_index = sgid_index;
	grh->hop_limit = hop_limit;
	grh->traffic_class = traffic_class;
}

static inline void rdma_ah_set_dgid_raw(struct rdma_ah_attr *attr, void *dgid)
{
	struct ib_global_route *grh = rdma_ah_read_grh(attr);

	memcpy(grh->dgid.raw, dgid, sizeof(grh->dgid));
}

#endif /* IONIC_HAVE_RDMA_AH_ATTR */
#ifndef IONIC_HAVE_IB_GET_ETH_SPEED
static inline int ib_get_eth_speed(struct ib_device *dev, u8 port_num,
				   u8 *speed, u8 *width)
{
	*width = IB_WIDTH_4X;
	*speed = IB_SPEED_EDR;
	return 0;
}

#endif /* IONIC_HAVE_IB_GET_ETH_SPEED */
#ifdef IONIC_HAVE_CUSTOM_IB_SET_DEVICE_OPS
struct ib_device_ops {
#ifdef IONIC_HAVE_CONST_IB_WR
	int (*post_send)(struct ib_qp *qp, const struct ib_send_wr *send_wr,
			 const struct ib_send_wr **bad_send_wr);
	int (*post_recv)(struct ib_qp *qp, const struct ib_recv_wr *recv_wr,
			 const struct ib_recv_wr **bad_recv_wr);
	int (*post_srq_recv)(struct ib_srq *srq,
			     const struct ib_recv_wr *recv_wr,
			     const struct ib_recv_wr **bad_recv_wr);
#else
	int (*post_send)(struct ib_qp *qp, struct ib_send_wr *send_wr,
			 struct ib_send_wr **bad_send_wr);
	int (*post_recv)(struct ib_qp *qp, struct ib_recv_wr *recv_wr,
			 struct ib_recv_wr **bad_recv_wr);
	int (*post_srq_recv)(struct ib_srq *srq,
			     struct ib_recv_wr *recv_wr,
			     struct ib_recv_wr **bad_recv_wr);
#endif /* IONIC_HAVE_CONST_IB_WR */
	void (*drain_rq)(struct ib_qp *qp);
	void (*drain_sq)(struct ib_qp *qp);
	int (*poll_cq)(struct ib_cq *cq, int num_entries, struct ib_wc *wc);
	int (*peek_cq)(struct ib_cq *cq, int wc_cnt);
	int (*req_notify_cq)(struct ib_cq *cq, enum ib_cq_notify_flags flags);
	int (*req_ncomp_notif)(struct ib_cq *cq, int wc_cnt);
	int (*query_device)(struct ib_device *device,
			    struct ib_device_attr *device_attr,
			    struct ib_udata *udata);
	int (*modify_device)(struct ib_device *device, int device_modify_mask,
			     struct ib_device_modify *device_modify);
#ifdef IONIC_HAVE_GET_DEV_FW_STR_LEN
	void (*get_dev_fw_str)(struct ib_device *device, char *str,
			       size_t str_len);
#else
	void (*get_dev_fw_str)(struct ib_device *device, char *str);
#endif
#ifdef IONIC_HAVE_GET_VECTOR_AFFINITY
	const struct cpumask *(*get_vector_affinity)(struct ib_device *ibdev,
						     int comp_vector);
#endif
	int (*query_port)(struct ib_device *device, u8 port_num,
			  struct ib_port_attr *port_attr);
	int (*modify_port)(struct ib_device *device, u8 port_num,
			   int port_modify_mask,
			   struct ib_port_modify *port_modify);
	int (*get_port_immutable)(struct ib_device *device, u8 port_num,
				  struct ib_port_immutable *immutable);
	enum rdma_link_layer (*get_link_layer)(struct ib_device *device,
					       u8 port_num);
	struct net_device *(*get_netdev)(struct ib_device *device,
					 u8 port_num);
#ifdef IONIC_HAVE_REQUIRED_IB_GID
	int (*query_gid)(struct ib_device *device, u8 port_num, int index,
			 union ib_gid *gid);
#ifdef IONIC_HAVE_IB_GID_DEV_PORT_INDEX
	int (*add_gid)(struct ib_device *device, u8 port, unsigned int index,
		       const union ib_gid *gid, const struct ib_gid_attr *attr,
		       void **context);
	int (*del_gid)(struct ib_device *device, u8 port, unsigned int index,
		       void **context);
#else
	int (*add_gid)(const union ib_gid *gid, const struct ib_gid_attr *attr,
		       void **context);
	int (*del_gid)(const struct ib_gid_attr *attr, void **context);
#endif /* IONIC_HAVE_IB_GID_DEV_PORT_INDEX */
#endif /* IONIC_HAVE_REQUIRED_IB_GID */
	int (*query_pkey)(struct ib_device *device, u8 port_num, u16 index,
			  u16 *pkey);
	struct ib_ucontext *(*alloc_ucontext)(struct ib_device *device,
					      struct ib_udata *udata);
	int (*dealloc_ucontext)(struct ib_ucontext *context);
	int (*mmap)(struct ib_ucontext *context, struct vm_area_struct *vma);
	void (*disassociate_ucontext)(struct ib_ucontext *ibcontext);
	struct ib_pd *(*alloc_pd)(struct ib_device *device,
				  struct ib_ucontext *context,
				  struct ib_udata *udata);
	int (*dealloc_pd)(struct ib_pd *pd);
#ifdef IONIC_HAVE_CREATE_AH_UDATA
#ifdef IONIC_HAVE_CREATE_AH_FLAGS
	struct ib_ah *(*create_ah)(struct ib_pd *pd,
				   struct rdma_ah_attr *ah_attr, u32 flags,
				   struct ib_udata *udata);
#else
	struct ib_ah *(*create_ah)(struct ib_pd *pd,
				   struct rdma_ah_attr *ah_attr,
				   struct ib_udata *udata);
#endif /* IONIC_HAVE_CREATE_AH_FLAGS */
#else
	struct ib_ah *(*create_ah)(struct ib_pd *pd,
				   struct rdma_ah_attr *ah_attr);
#endif /* IONIC_HAVE_CREATE_AH_UDATA */
	int (*modify_ah)(struct ib_ah *ah, struct rdma_ah_attr *ah_attr);
	int (*query_ah)(struct ib_ah *ah, struct rdma_ah_attr *ah_attr);
#ifdef IONIC_HAVE_DESTROY_AH_FLAGS
	int (*destroy_ah)(struct ib_ah *ah, u32 flags);
#else
	int (*destroy_ah)(struct ib_ah *ah);
#endif
	struct ib_srq *(*create_srq)(struct ib_pd *pd,
				     struct ib_srq_init_attr *srq_init_attr,
				     struct ib_udata *udata);
	int (*modify_srq)(struct ib_srq *srq, struct ib_srq_attr *srq_attr,
			  enum ib_srq_attr_mask srq_attr_mask,
			  struct ib_udata *udata);
	int (*query_srq)(struct ib_srq *srq, struct ib_srq_attr *srq_attr);
	int (*destroy_srq)(struct ib_srq *srq);
	struct ib_qp *(*create_qp)(struct ib_pd *pd,
				   struct ib_qp_init_attr *qp_init_attr,
				   struct ib_udata *udata);
	int (*modify_qp)(struct ib_qp *qp, struct ib_qp_attr *qp_attr,
			 int qp_attr_mask, struct ib_udata *udata);
	int (*query_qp)(struct ib_qp *qp, struct ib_qp_attr *qp_attr,
			int qp_attr_mask,
			struct ib_qp_init_attr *qp_init_attr);
	int (*destroy_qp)(struct ib_qp *qp);
	struct ib_cq *(*create_cq)(struct ib_device *device,
				   const struct ib_cq_init_attr *attr,
				   struct ib_ucontext *context,
				   struct ib_udata *udata);
	int (*modify_cq)(struct ib_cq *cq, u16 cq_count, u16 cq_period);
	int (*destroy_cq)(struct ib_cq *cq);
	int (*resize_cq)(struct ib_cq *cq, int cqe, struct ib_udata *udata);
	struct ib_mr *(*get_dma_mr)(struct ib_pd *pd, int mr_access_flags);
#ifdef IONIC_HAVE_IB_USER_MR_INIT_ATTR
	struct ib_mr *(*reg_user_mr)(struct ib_pd *pd,
				     struct ib_mr_init_attr *attr,
				     struct ib_udata *udata);
#else
	struct ib_mr *(*reg_user_mr)(struct ib_pd *pd, u64 start, u64 length,
				     u64 virt_addr, int mr_access_flags,
				     struct ib_udata *udata);
#endif
	int (*rereg_user_mr)(struct ib_mr *mr, int flags, u64 start,
			     u64 length, u64 virt_addr, int mr_access_flags,
			     struct ib_pd *pd, struct ib_udata *udata);
	int (*dereg_mr)(struct ib_mr *mr);
	struct ib_mr *(*alloc_mr)(struct ib_pd *pd, enum ib_mr_type mr_type,
				  u32 max_num_sg);
	int (*map_mr_sg)(struct ib_mr *mr, struct scatterlist *sg,
			 int sg_nents, unsigned int *sg_offset);
	int (*check_mr_status)(struct ib_mr *mr, u32 check_mask,
			       struct ib_mr_status *mr_status);
	struct ib_mw *(*alloc_mw)(struct ib_pd *pd, enum ib_mw_type type,
				  struct ib_udata *udata);
	int (*dealloc_mw)(struct ib_mw *mw);
	int (*attach_mcast)(struct ib_qp *qp, union ib_gid *gid, u16 lid);
	int (*detach_mcast)(struct ib_qp *qp, union ib_gid *gid, u16 lid);
	struct ib_xrcd *(*alloc_xrcd)(struct ib_device *device,
				      struct ib_ucontext *ucontext,
				      struct ib_udata *udata);
	int (*dealloc_xrcd)(struct ib_xrcd *xrcd);
	struct rdma_hw_stats *(*alloc_hw_stats)(struct ib_device *device,
						u8 port_num);
	int (*get_hw_stats)(struct ib_device *device,
			    struct rdma_hw_stats *stats, u8 port, int index);
};

static inline void ib_set_device_ops(struct ib_device *dev,
				     const struct ib_device_ops *ops)
{
#define SET_DEVICE_OP(name) \
	(dev->name = dev->name ?: ops->name)

#ifdef IONIC_HAVE_REQUIRED_IB_GID
	SET_DEVICE_OP(add_gid);
#endif
	SET_DEVICE_OP(alloc_hw_stats);
	SET_DEVICE_OP(alloc_mr);
	SET_DEVICE_OP(alloc_mw);
	SET_DEVICE_OP(alloc_pd);
	SET_DEVICE_OP(alloc_ucontext);
	SET_DEVICE_OP(alloc_xrcd);
	SET_DEVICE_OP(attach_mcast);
	SET_DEVICE_OP(check_mr_status);
	SET_DEVICE_OP(create_ah);
	SET_DEVICE_OP(create_cq);
	SET_DEVICE_OP(create_qp);
	SET_DEVICE_OP(create_srq);
	SET_DEVICE_OP(dealloc_mw);
	SET_DEVICE_OP(dealloc_pd);
	SET_DEVICE_OP(dealloc_ucontext);
	SET_DEVICE_OP(dealloc_xrcd);
#ifdef IONIC_HAVE_REQUIRED_IB_GID
	SET_DEVICE_OP(del_gid);
#endif
	SET_DEVICE_OP(dereg_mr);
	SET_DEVICE_OP(destroy_ah);
	SET_DEVICE_OP(destroy_cq);
	SET_DEVICE_OP(destroy_qp);
	SET_DEVICE_OP(destroy_srq);
	SET_DEVICE_OP(detach_mcast);
	SET_DEVICE_OP(disassociate_ucontext);
	SET_DEVICE_OP(drain_rq);
	SET_DEVICE_OP(drain_sq);
#ifdef IONIC_HAVE_GET_DEV_FW_STR
	SET_DEVICE_OP(get_dev_fw_str);
#endif
	SET_DEVICE_OP(get_dma_mr);
	SET_DEVICE_OP(get_hw_stats);
	SET_DEVICE_OP(get_link_layer);
	SET_DEVICE_OP(get_netdev);
	SET_DEVICE_OP(get_port_immutable);
#ifdef IONIC_HAVE_GET_VECTOR_AFFINITY
	SET_DEVICE_OP(get_vector_affinity);
#endif
	SET_DEVICE_OP(map_mr_sg);
	SET_DEVICE_OP(mmap);
	SET_DEVICE_OP(modify_ah);
	SET_DEVICE_OP(modify_cq);
	SET_DEVICE_OP(modify_device);
	SET_DEVICE_OP(modify_port);
	SET_DEVICE_OP(modify_qp);
	SET_DEVICE_OP(modify_srq);
	SET_DEVICE_OP(peek_cq);
	SET_DEVICE_OP(poll_cq);
	SET_DEVICE_OP(post_recv);
	SET_DEVICE_OP(post_send);
	SET_DEVICE_OP(post_srq_recv);
	SET_DEVICE_OP(query_ah);
	SET_DEVICE_OP(query_device);
#ifdef IONIC_HAVE_REQUIRED_IB_GID
	SET_DEVICE_OP(query_gid);
#endif
	SET_DEVICE_OP(query_pkey);
	SET_DEVICE_OP(query_port);
	SET_DEVICE_OP(query_qp);
	SET_DEVICE_OP(query_srq);
	SET_DEVICE_OP(reg_user_mr);
	SET_DEVICE_OP(req_ncomp_notif);
	SET_DEVICE_OP(req_notify_cq);
	SET_DEVICE_OP(rereg_user_mr);
	SET_DEVICE_OP(resize_cq);
#undef SET_DEVICE_OP
}

#endif /* IONIC_HAVE_CUSTOM_IB_SET_DEVICE_OPS */
#ifdef IONIC_HAVE_IB_PORT_PHYS_STATE
enum ib_port_phys_state {
	IB_PORT_PHYS_STATE_SLEEP = 1,
	IB_PORT_PHYS_STATE_POLLING = 2,
	IB_PORT_PHYS_STATE_DISABLED = 3,
	IB_PORT_PHYS_STATE_PORT_CONFIGURATION_TRAINING = 4,
	IB_PORT_PHYS_STATE_LINK_UP = 5,
	IB_PORT_PHYS_STATE_LINK_ERROR_RECOVERY = 6,
	IB_PORT_PHYS_STATE_PHY_TEST = 7,
};

#endif /* IONIC_HAVE_IB_PORT_PHYS_STATE */

#if defined(IONIC_HAVE_DEVOPS_DEVICE_GROUP) || defined(IONIC_HAVE_RDMA_SET_DEVICE_GROUP)
#define IONIC_HAVE_RDMA_DEVICE_GROUP
#endif

#ifdef BROKEN_IBDEV_PRINT
#define IONIC_HAVE_IBDEV_PRINT
#undef ibdev_dbg
#undef ibdev_info
#undef ibdev_warn
#undef ibdev_err
#endif /* BROKEN_IBDEV_PRINT */

#ifdef IONIC_HAVE_IBDEV_PRINT
#define ibdev_dbg(ibdev, ...)	dev_dbg(&(ibdev)->dev, ##__VA_ARGS__)
#define ibdev_info(ibdev, ...)	dev_info(&(ibdev)->dev, ##__VA_ARGS__)
#define ibdev_warn(ibdev, ...)	dev_warn(&(ibdev)->dev, ##__VA_ARGS__)
#define ibdev_err(ibdev, ...)	dev_err(&(ibdev)->dev, ##__VA_ARGS__)

#endif /* IONIC_HAVE_IBDEV_PRINT */
#ifdef IONIC_HAVE_IBDEV_PRINT_RATELIMITED
#define ibdev_warn_ratelimited(ibdev, ...)				\
	dev_warn_ratelimited(&(ibdev)->dev, ##__VA_ARGS__)

#endif /* IONIC_HAVE_IBDEV_PRINT_RATELIMITED */
#endif /* IONIC_KCOMPAT_H */
