// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2018-2020 Pensando Systems, Inc.  All rights reserved.
 */

#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/pci.h>
#include <linux/irq.h>
#include <linux/mman.h>
#include <net/addrconf.h>
#include <rdma/ib_addr.h>
#include <rdma/ib_cache.h>
#include <rdma/ib_mad.h>
#include <rdma/ib_pack.h>
#include <rdma/ib_user_verbs.h>

#include "ionic_fw.h"
#include "ionic_ibdev.h"

MODULE_AUTHOR("Allen Hubbe <allen.hubbe@amd.com>");
MODULE_DESCRIPTION("Pensando RoCE HCA driver");
MODULE_LICENSE("Dual BSD/GPL");

#ifdef IONIC_NOT_UPSTREAM
/* module version not to be upstreamed */
#ifndef IONIC_DRV_VERSION
#define IONIC_DRV_VERSION	drv_ver
#endif
MODULE_VERSION(IONIC_DRV_VERSION);
#endif

#define DRIVER_DESCRIPTION "Pensando RoCE HCA driver"
#define DEVICE_DESCRIPTION "Pensando RoCE HCA"

#define IONIC_VERSION(a, b) (((a) << 16) + ((b) << 8))

static const struct auxiliary_device_id ionic_aux_id_table[] = {
	{ .name = IONIC_AUX_DEVNAME, },
	{},
};

MODULE_DEVICE_TABLE(auxiliary, ionic_aux_id_table);

static int ionic_qid_skip = 512;
static void ionic_resid_skip(struct ionic_resid_bits *bits)
{
	int i = ionic_qid_skip - 1;

	while (i < bits->inuse_size) {
		set_bit(i, bits->inuse);
		i += ionic_qid_skip;
	}
}

// TODO: delete this after plan-A/B both have qgroup-oriented udma
static void ionic_resid_skip_lohi(struct ionic_resid_bits *bits)
{
	int i;

	/* mark all odd-numbered low qids to they can't be used */
	for (i = 3; i < bits->inuse_size / 2; i += 2)
		set_bit(i, bits->inuse);

	/* mark all even-numbered high qids to they can't be used */
	for (i = bits->inuse_size / 2; i < bits->inuse_size; i += 2)
		set_bit(i, bits->inuse);

	/* except for the reserved qids 0 and 1, only even-numbered low qids and
	 * odd-numbered high qids remain available to use.
	 */
}

static int ionic_query_device(struct ib_device *ibdev,
			      struct ib_device_attr *attr,
			      struct ib_udata *udata)
{
	struct ionic_ibdev *dev = to_ionic_ibdev(ibdev);

	addrconf_ifid_eui48((u8 *)&attr->sys_image_guid, dev->ndev);
	attr->max_mr_size =
		le32_to_cpu(dev->ident->rdma.npts_per_lif) * PAGE_SIZE / 2;
	attr->page_size_cap = dev->page_size_supported;
	if (dev_is_pci(dev->hwdev)) {
		attr->vendor_id = to_pci_dev(dev->hwdev)->vendor;
		attr->vendor_part_id = to_pci_dev(dev->hwdev)->device;
	}
	attr->hw_ver = dev->info->asic_rev;
	attr->fw_ver = 0;
	attr->max_qp = dev->size_qpid;
	attr->max_qp_wr = IONIC_MAX_DEPTH;
	attr->device_cap_flags =
#ifndef IONIC_HAVE_IB_KERNEL_CAP_FLAGS
		IB_DEVICE_LOCAL_DMA_LKEY |
#endif
		IB_DEVICE_MEM_WINDOW |
		IB_DEVICE_MEM_MGT_EXTENSIONS |
		IB_DEVICE_MEM_WINDOW_TYPE_2B |
		0;
#ifdef IONIC_HAVE_IB_KERNEL_CAP_FLAGS
	attr->kernel_cap_flags = IBK_LOCAL_DMA_LKEY;
#endif
#ifdef IONIC_HAVE_IBDEV_MAX_SEND_RECV_SGE
	attr->max_send_sge =
		min(ionic_v1_send_wqe_max_sge(dev->max_stride, 0, false),
		    ionic_spec);
	attr->max_recv_sge =
		min(ionic_v1_recv_wqe_max_sge(dev->max_stride, 0, false),
		    ionic_spec);
	attr->max_sge_rd = attr->max_send_sge;
#else
	attr->max_sge =
		min3(ionic_v1_send_wqe_max_sge(dev->max_stride, 0, false),
		     ionic_v1_recv_wqe_max_sge(dev->max_stride, 0, false),
		     ionic_spec);
	attr->max_sge_rd = attr->max_sge;
#endif
	attr->max_cq = dev->inuse_cqid.inuse_size / dev->udma_count;
	attr->max_cqe = IONIC_MAX_CQ_DEPTH - IONIC_CQ_GRACE;
	attr->max_mr = dev->inuse_mrid.inuse_size;
	attr->max_pd = ionic_max_pd;
	attr->max_qp_rd_atom = IONIC_MAX_RD_ATOM;
	attr->max_ee_rd_atom = 0;
	attr->max_res_rd_atom = IONIC_MAX_RD_ATOM;
	attr->max_qp_init_rd_atom = IONIC_MAX_RD_ATOM;
	attr->max_ee_init_rd_atom = 0;
	attr->atomic_cap = IB_ATOMIC_GLOB;
	attr->masked_atomic_cap = IB_ATOMIC_GLOB;
	attr->max_mw = dev->inuse_mrid.inuse_size;
	attr->max_mcast_grp = 0;
	attr->max_mcast_qp_attach = 0;
	attr->max_ah = dev->inuse_ahid.inuse_size;
	attr->max_fast_reg_page_list_len =
		le32_to_cpu(dev->ident->rdma.npts_per_lif) / 2;
	attr->max_pkeys = IONIC_PKEY_TBL_LEN;

	return 0;
}

#ifdef IONIC_HAVE_IB_PORT_U32
static int ionic_query_port(struct ib_device *ibdev, u32 port,
			    struct ib_port_attr *attr)
#else
static int ionic_query_port(struct ib_device *ibdev, u8 port,
			    struct ib_port_attr *attr)
#endif
{
	struct ionic_ibdev *dev = to_ionic_ibdev(ibdev);
	struct net_device *ndev = dev->ndev;

	if (port != 1)
		return -EINVAL;

	if (netif_running(ndev) && netif_carrier_ok(ndev)) {
		attr->state = IB_PORT_ACTIVE;
		attr->phys_state = IB_PORT_PHYS_STATE_LINK_UP;
	} else if (netif_running(ndev)) {
		attr->state = IB_PORT_DOWN;
		attr->phys_state = IB_PORT_PHYS_STATE_POLLING;
	} else {
		attr->state = IB_PORT_DOWN;
		attr->phys_state = IB_PORT_PHYS_STATE_DISABLED;
	}

#ifdef IONIC_HAVE_NETDEV_MAX_MTU
	attr->max_mtu = iboe_get_mtu(ndev->max_mtu);
#else
	attr->max_mtu = IB_MTU_4096;
#endif
	attr->active_mtu = min(attr->max_mtu, iboe_get_mtu(ndev->mtu));
	attr->gid_tbl_len = IONIC_GID_TBL_LEN;
#ifdef IONIC_HAVE_PORT_ATTR_IP_GIDS
	attr->ip_gids = true;
	attr->port_cap_flags = 0;
#else
	attr->port_cap_flags = IB_PORT_IP_BASED_GIDS;
#endif
	attr->max_msg_sz = 0x80000000;
	attr->pkey_tbl_len = IONIC_PKEY_TBL_LEN;
	attr->max_vl_num = 1;
	attr->subnet_prefix = 0xfe80000000000000ull;

	return ib_get_eth_speed(ibdev, port,
				&attr->active_speed,
				&attr->active_width);
}

#ifdef IONIC_HAVE_IB_PORT_U32
static enum rdma_link_layer ionic_get_link_layer(struct ib_device *ibdev,
						 u32 port)
#else
static enum rdma_link_layer ionic_get_link_layer(struct ib_device *ibdev,
						 u8 port)
#endif
{
	return IB_LINK_LAYER_ETHERNET;
}

#ifdef IONIC_HAVE_IB_PORT_U32
static struct net_device *ionic_get_netdev(struct ib_device *ibdev, u32 port)
#else
static struct net_device *ionic_get_netdev(struct ib_device *ibdev, u8 port)
#endif
{
	struct ionic_ibdev *dev = to_ionic_ibdev(ibdev);

	if (port != 1)
		return ERR_PTR(-EINVAL);

	dev_hold(dev->ndev);

	return dev->ndev;
}

#ifdef IONIC_HAVE_REQUIRED_IB_GID
static int ionic_query_gid(struct ib_device *ibdev, u8 port, int index,
			   union ib_gid *gid)
{
	int rc;

	rc = ib_get_cached_gid(ibdev, port, index, gid, NULL);
	if (rc == -EAGAIN) {
		memcpy(gid, &zgid, sizeof(*gid));
		return 0;
	}

	return rc;
}

#ifdef IONIC_HAVE_IB_GID_DEV_PORT_INDEX
static int ionic_add_gid(struct ib_device *ibdev, u8 port,
			 unsigned int index, const union ib_gid *gid,
			 const struct ib_gid_attr *attr, void **context)
#else
static int ionic_add_gid(const union ib_gid *gid,
			 const struct ib_gid_attr *attr, void **context)
#endif
{
	if (attr->gid_type == IB_GID_TYPE_IB)
		return -EINVAL;

	return 0;
}

#ifdef IONIC_HAVE_IB_GID_DEV_PORT_INDEX
static int ionic_del_gid(struct ib_device *ibdev, u8 port,
			 unsigned int index, void **context)
#else
static int ionic_del_gid(const struct ib_gid_attr *attr, void **context)
#endif /* IONIC_HAVE_IB_GID_DEV_PORT_INDEX */
{
	return 0;
}

#endif /* IONIC_HAVE_REQUIRED_IB_GID */
#ifdef IONIC_HAVE_IB_PORT_U32
static int ionic_query_pkey(struct ib_device *ibdev, u32 port, u16 index,
			    u16 *pkey)
#else
static int ionic_query_pkey(struct ib_device *ibdev, u8 port, u16 index,
			    u16 *pkey)
#endif
{
	if (port != 1)
		return -EINVAL;

	if (index != 0)
		return -EINVAL;

	*pkey = 0xffff;

	return 0;
}

static int ionic_modify_device(struct ib_device *ibdev, int mask,
			       struct ib_device_modify *attr)
{
	struct ionic_ibdev *dev = to_ionic_ibdev(ibdev);

	if (mask & ~IB_DEVICE_MODIFY_NODE_DESC)
		return -EOPNOTSUPP;

	if (mask & IB_DEVICE_MODIFY_NODE_DESC)
		memcpy(dev->ibdev.node_desc, attr->node_desc,
		       IB_DEVICE_NODE_DESC_MAX);

	return 0;
}

#ifdef HAVE_MANDATORY_IB_MODIFY_PORT
static int ionic_modify_port(struct ib_device *ibdev, u8 port, int mask,
			     struct ib_port_modify *attr)
{
	return 0;
}

#endif /* HAVE_MANDATORY_IB_MODIFY_PORT */
#ifdef IONIC_HAVE_IB_PORT_U32
static int ionic_get_port_immutable(struct ib_device *ibdev, u32 port,
				    struct ib_port_immutable *attr)
#else
static int ionic_get_port_immutable(struct ib_device *ibdev, u8 port,
				    struct ib_port_immutable *attr)
#endif
{
	if (port != 1)
		return -EINVAL;

	attr->core_cap_flags = RDMA_CORE_PORT_IBA_ROCE_UDP_ENCAP;

	attr->pkey_tbl_len = IONIC_PKEY_TBL_LEN;
	attr->gid_tbl_len = IONIC_GID_TBL_LEN;
	attr->max_mad_size = IB_MGMT_MAD_SIZE;

	return 0;
}

#ifdef IONIC_HAVE_GET_DEV_FW_STR_LEN
static void ionic_get_dev_fw_str(struct ib_device *ibdev, char *str,
				 size_t str_len)
#else
static void ionic_get_dev_fw_str(struct ib_device *ibdev, char *str)
#endif
{
	struct ionic_ibdev *dev = to_ionic_ibdev(ibdev);
#ifndef IONIC_HAVE_GET_DEV_FW_STR_LEN
	size_t str_len = IB_FW_VERSION_NAME_MAX;
#endif

	strscpy(str, dev->info->fw_version, str_len);
}

#ifdef IONIC_HAVE_GET_VECTOR_AFFINITY
static const struct cpumask *ionic_get_vector_affinity(struct ib_device *ibdev,
						       int comp_vector)
{
	struct ionic_ibdev *dev = to_ionic_ibdev(ibdev);

	if (comp_vector < 0 || comp_vector >= dev->eq_count)
		return NULL;

	return irq_get_affinity_mask(dev->eq_vec[comp_vector]->irq);
}

#endif
void ionic_port_event(struct ionic_ibdev *dev, enum ib_event_type event)
{
	struct ib_event ev;

	ev.device = &dev->ibdev;
	ev.element.port_num = 1;
	ev.event = event;

	ib_dispatch_event(&ev);
}

static void ionic_destroy_ibdev(struct ionic_ibdev *dev)
{
	struct net_device *ndev = dev->ndev;

	ionic_kill_rdma_admin(dev, false);

	ionic_dcqcn_destroy(dev);
	ionic_stats_cleanup(dev);

	ib_unregister_device(&dev->ibdev);

	ionic_destroy_rdma_admin(dev);

	ionic_api_clear_private(dev->handle);

	ionic_stats_print(&dev->ibdev.dev, dev->stats);
	kfree(dev->stats);

	ionic_lats_print(&dev->ibdev.dev, dev->lats);
	kfree(dev->lats);

	ionic_dbg_rm_dev(dev);

	ionic_resid_destroy(&dev->inuse_qpid);
	ionic_resid_destroy(&dev->inuse_cqid);
	ionic_resid_destroy(&dev->inuse_mrid);
	ionic_resid_destroy(&dev->inuse_ahid);
	ionic_resid_destroy(&dev->inuse_pdid);
	xa_destroy(&dev->qp_tbl);
	xa_destroy(&dev->cq_tbl);

	ib_dealloc_device(&dev->ibdev);

	dev_put(ndev);
}

static void ionic_kill_ibdev_cb(void *dev_ptr)
{
	struct ionic_ibdev *dev = dev_ptr;

	ibdev_warn(&dev->ibdev, "reset callback starting\n");

	ionic_kill_ibdev(dev, true);
}

#ifdef IONIC_HAVE_RDMA_DEVICE_GROUP
static ssize_t hw_rev_show(struct device *device, struct device_attribute *attr,
			   char *buf)
{
	struct ionic_ibdev *dev =
		rdma_device_to_drv_device(device, struct ionic_ibdev, ibdev);

	return sysfs_emit(buf, "0x%x\n", dev->info->asic_rev);
}
static DEVICE_ATTR_RO(hw_rev);

static ssize_t hca_type_show(struct device *device,
			     struct device_attribute *attr, char *buf)
{
	struct ionic_ibdev *dev =
		rdma_device_to_drv_device(device, struct ionic_ibdev, ibdev);

	return sysfs_emit(buf, "%s\n", dev->ibdev.node_desc);
}
static DEVICE_ATTR_RO(hca_type);

static struct attribute *ionic_rdma_attributes[] = {
	&dev_attr_hw_rev.attr,
	&dev_attr_hca_type.attr,
	NULL
};

static const struct attribute_group ionic_rdma_attr_group = {
	.attrs = ionic_rdma_attributes,
};
#endif

static void ionic_disassociate_ucontext(struct ib_ucontext *ibcontext)
{
}
static const struct ib_device_ops ionic_dev_ops = {
#ifdef IONIC_HAVE_RDMA_DEV_OPS_EXT
	.owner			= THIS_MODULE,
	.driver_id		= RDMA_DRIVER_IONIC,
	.uverbs_abi_ver		= IONIC_ABI_VERSION,
#endif
	.query_device		= ionic_query_device,
	.query_port		= ionic_query_port,
	.get_link_layer		= ionic_get_link_layer,
	.get_netdev		= ionic_get_netdev,
#ifdef IONIC_HAVE_REQUIRED_IB_GID
	.query_gid		= ionic_query_gid,
	.add_gid		= ionic_add_gid,
	.del_gid		= ionic_del_gid,
#endif
	.query_pkey		= ionic_query_pkey,
	.modify_device		= ionic_modify_device,
#ifdef HAVE_MANDATORY_IB_MODIFY_PORT
	.modify_port		= ionic_modify_port,
#endif

	.get_port_immutable	= ionic_get_port_immutable,
	.get_dev_fw_str		= ionic_get_dev_fw_str,
#ifdef IONIC_HAVE_GET_VECTOR_AFFINITY
	.get_vector_affinity	= ionic_get_vector_affinity,
#endif
#ifdef IONIC_HAVE_DEVOPS_DEVICE_GROUP
	.device_group		= &ionic_rdma_attr_group,
#endif
	.disassociate_ucontext	= ionic_disassociate_ucontext,
};

static struct ionic_ibdev *ionic_create_ibdev(void *handle,
					      struct net_device *ndev)
{
	struct ib_device *ibdev;
	struct ionic_ibdev *dev;
	struct device *hwdev;
	const union ionic_lif_identity *ident;
	struct dentry *dbg_ctx;
	int rc, val, lif_index, version;
	// TODO: delete this after plan-A/B both use qgroup-oriented udma.
	bool xxx_udma_lohi = false;

	dev_hold(ndev);

	ident = ionic_api_get_identity(handle, &lif_index);

	netdev_dbg(ndev, "rdma.version %d\n",
		ident->rdma.version);
	netdev_dbg(ndev, "rdma.minor_version %d\n", ident->rdma.minor_version);
	netdev_dbg(ndev, "rdma.qp_opcodes %d\n",
		ident->rdma.qp_opcodes);
	netdev_dbg(ndev, "rdma.admin_opcodes %d\n",
		ident->rdma.admin_opcodes);
	netdev_dbg(ndev, "rdma.npts_per_lif %d\n",
		ident->rdma.npts_per_lif);
	netdev_dbg(ndev, "rdma.nmrs_per_lif %d\n",
		ident->rdma.nmrs_per_lif);
	netdev_dbg(ndev, "rdma.nahs_per_lif %d\n",
		ident->rdma.nahs_per_lif);
	netdev_dbg(ndev, "rdma.aq.qtype %d rdma.aq.base %d rdma.aq.count %d\n",
		ident->rdma.aq_qtype.qtype,
		ident->rdma.aq_qtype.qid_base, ident->rdma.aq_qtype.qid_count);
	netdev_dbg(ndev, "rdma.sq.qtype %d rdma.sq.base %d rdma.sq.count %d\n",
		ident->rdma.sq_qtype.qtype,
		ident->rdma.sq_qtype.qid_base, ident->rdma.sq_qtype.qid_count);
	netdev_dbg(ndev, "rdma.rq.qtype %d rdma.rq.base %d rdma.rq.count %d\n",
		ident->rdma.rq_qtype.qtype,
		ident->rdma.rq_qtype.qid_base, ident->rdma.rq_qtype.qid_count);
	netdev_dbg(ndev, "rdma.cq.qtype %d rdma.cq.base %d rdma.cq.count %d\n",
		ident->rdma.cq_qtype.qtype,
		ident->rdma.cq_qtype.qid_base, ident->rdma.cq_qtype.qid_count);
	netdev_dbg(ndev, "rdma.eq.qtype %d rdma.eq.base %d rdma.eq.count %d\n",
		ident->rdma.eq_qtype.qtype,
		ident->rdma.eq_qtype.qid_base, ident->rdma.eq_qtype.qid_count);

	version = ident->rdma.version;

	if (version < IONIC_MIN_RDMA_VERSION) {
		netdev_err(ndev,
			   FW_INFO "ionic_rdma: Firmware RDMA Version %u\n",
			   version);
		netdev_err(ndev,
			   FW_INFO "ionic_rdma: Driver Min RDMA Version %u\n",
			   IONIC_MIN_RDMA_VERSION);
		rc = -EINVAL;
		goto err_dev;
	}

	if (version > IONIC_MAX_RDMA_VERSION) {
		netdev_err(ndev,
			   FW_INFO "ionic_rdma: Firmware RDMA Version %u\n",
			   version);
		netdev_err(ndev,
			   FW_INFO "ionic_rdma: Driver Max RDMA Version %u\n",
			   IONIC_MAX_RDMA_VERSION);
		rc = -EINVAL;
		goto err_dev;
	}

	hwdev = ionic_api_get_device(handle);

#ifndef IONIC_HAVE_IB_ALLOC_DEV_NO_CONTAINER
	dev = ib_alloc_device(ionic_ibdev, ibdev);
	if (!dev) {
		rc = -ENOMEM;
		goto err_dev;
	}
	ibdev = &dev->ibdev;
#else
	ibdev = ib_alloc_device(sizeof(*dev));
	if (!ibdev) {
		rc = -ENOMEM;
		goto err_dev;
	}
	dev = to_ionic_ibdev(ibdev);
#endif

	dev->hwdev = hwdev;
	dev->ndev = ndev;
	dev->handle = handle;
	dev->lif_index = lif_index;
	dev->ident = ident;
	dev->info = ionic_api_get_devinfo(handle);

	ionic_api_kernel_dbpage(handle, &dev->intr_ctrl,
				&dev->dbid, &dev->dbpage);

	dev->rdma_version = version;
	dev->qp_opcodes = ident->rdma.qp_opcodes;
	dev->admin_opcodes = ident->rdma.admin_opcodes;

	if (IONIC_VERSION(ident->rdma.version, ident->rdma.minor_version) >= IONIC_VERSION(2, 1))
		dev->page_size_supported = cpu_to_le64(ident->rdma.page_size_cap);
	else
		dev->page_size_supported = IONIC_PAGE_SIZE_SUPPORTED;

	/* base opcodes must be supported, extended opcodes are optional */
	if (dev->rdma_version == 1 && dev->qp_opcodes <= IONIC_V1_OP_BIND_MW) {
		netdev_dbg(ndev, "ionic_rdma: qp opcodes %d want min %d\n",
			   dev->qp_opcodes, IONIC_V1_OP_BIND_MW + 1);
		rc = -ENODEV;
		goto err_dev;
	}

	/* need at least one rdma admin queue (driver creates one) */
	val = le32_to_cpu(ident->rdma.aq_qtype.qid_count);
	if (!val) {
		netdev_dbg(ndev, "ionic_rdma: No RDMA Admin Queue\n");
		rc = -ENODEV;
		goto err_dev;
	}

	/* qp ids start at zero, and sq id == qp id */
	val = le32_to_cpu(ident->rdma.sq_qtype.qid_base);
	if (val) {
		netdev_dbg(ndev, "ionic_rdma: Nonzero sq qid base %u\n", val);
		rc = -EINVAL;
		goto err_dev;
	}

	/* qp ids start at zero, and rq id == qp id */
	val = le32_to_cpu(ident->rdma.rq_qtype.qid_base);
	if (val) {
		netdev_dbg(ndev, "ionic_rdma: Nonzero rq qid base %u\n", val);
		rc = -EINVAL;
		goto err_dev;
	}

	/* driver supports these qtypes starting at nonzero base */
	dev->aq_base = le32_to_cpu(ident->rdma.aq_qtype.qid_base);
	dev->cq_base = le32_to_cpu(ident->rdma.cq_qtype.qid_base);
	dev->eq_base = le32_to_cpu(ident->rdma.eq_qtype.qid_base);

	/*
	 * ionic_create_rdma_admin() may reduce aq_count or eq_count if
	 * it is unable to allocate all that were requested.
	 * aq_count is tunable; see ionic_aq_count
	 * eq_count is tunable; see ionic_eq_count
	 */
	dev->aq_count = le32_to_cpu(ident->rdma.aq_qtype.qid_count);
	dev->eq_count = le32_to_cpu(ident->rdma.eq_qtype.qid_count);

	dev->aq_qtype = ident->rdma.aq_qtype.qtype;
	dev->sq_qtype = ident->rdma.sq_qtype.qtype;
	dev->rq_qtype = ident->rdma.rq_qtype.qtype;
	dev->cq_qtype = ident->rdma.cq_qtype.qtype;
	dev->eq_qtype = ident->rdma.eq_qtype.qtype;

	dev->max_stride = ident->rdma.max_stride;
	dev->cl_stride = ident->rdma.cl_stride;
	dev->pte_stride = ident->rdma.pte_stride;
	dev->rrq_stride = ident->rdma.rrq_stride;
	dev->rsq_stride = ident->rdma.rsq_stride;

	dev->expdb_mask = ionic_api_get_expdb(dev->handle);
	if (dev->expdb_mask) {
		struct ionic_qtype_info qti;

		// TODO: use an rdma-specific qtype (nicmgr change)
		if (!ionic_api_get_queue_identity(dev->handle, IONIC_QTYPE_TXQ, &qti))
			dev->sq_expdb = !!(qti.features & IONIC_QIDENT_F_EXPDB);

		if (!ionic_api_get_queue_identity(dev->handle, IONIC_QTYPE_RXQ, &qti))
			dev->rq_expdb = !!(qti.features & IONIC_QIDENT_F_EXPDB);
	}

	dev->udma_qgrp_shift = ident->rdma.udma_shift;
	if (dev->udma_qgrp_shift > 23) {
		netdev_err(ndev, "ionic_rdma: bogus udma shift %u\n",
			   dev->udma_qgrp_shift);
		rc = -EINVAL;
		goto err_dev;
	}

	// TODO: delete this after plan-A/B both have qgroup-oriented udma
	if (!dev->udma_qgrp_shift) {
		netdev_err(ndev, FW_INFO "ionic_rdma: XXX deprecated lo-hi udma\n");
		xxx_udma_lohi = true;
		dev->udma_qgrp_shift =
			order_base_2(le32_to_cpu(ident->rdma.sq_qtype.qid_count) / 2);
	}

	if (!dev->udma_qgrp_shift)
		dev->udma_count = 1;
	else
		dev->udma_count = 2;

	xa_init_flags(&dev->qp_tbl, GFP_ATOMIC);
	rwlock_init(&dev->qp_tbl_rw);
	xa_init_flags(&dev->cq_tbl, GFP_ATOMIC);
	rwlock_init(&dev->cq_tbl_rw);

	mutex_init(&dev->inuse_lock);
	spin_lock_init(&dev->inuse_splock);

	rc = ionic_resid_init(&dev->inuse_pdid, ionic_max_pd);
	if (rc)
		goto err_pdid;

	rc = ionic_resid_init(&dev->inuse_ahid,
			      le32_to_cpu(ident->rdma.nahs_per_lif));
	if (rc)
		goto err_ahid;

	rc = ionic_resid_init(&dev->inuse_mrid,
			      le32_to_cpu(ident->rdma.nmrs_per_lif));
	if (rc)
		goto err_mrid;

	/* skip reserved lkey */
	dev->inuse_mrid.next_id = 1;
	dev->next_mrkey = 1;

	rc = ionic_resid_init(&dev->inuse_cqid,
			      le32_to_cpu(ident->rdma.cq_qtype.qid_count));
	if (rc)
		goto err_cqid;

	dev->next_cqid[0] = 0;
	dev->next_cqid[1] = dev->inuse_cqid.inuse_size / dev->udma_count;
	dev->half_cqid_udma_shift =
		order_base_2(dev->inuse_cqid.inuse_size / dev->udma_count);

	dev->size_qpid = le32_to_cpu(ident->rdma.sq_qtype.qid_count);
	rc = ionic_resid_init(&dev->inuse_qpid, dev->size_qpid);
	if (rc)
		goto err_qpid;

	/* skip reserved SMI and GSI qpids */
	dev->next_qpid[0] = 2;
	dev->next_qpid[1] = dev->size_qpid / dev->udma_count;
	dev->half_qpid_udma_shift =
		order_base_2(dev->size_qpid / dev->udma_count);

	if (dev->rdma_version == 1 && ionic_qid_skip > 0) {
		ionic_resid_skip(&dev->inuse_qpid);
		ionic_resid_skip(&dev->inuse_cqid);
	}

	// TODO: delete this after plan-A/B both have qgroup-oriented udma
	if (xxx_udma_lohi) {
		netdev_err(ndev, FW_INFO "ionic_rdma: XXX deprecated even-odd udma\n");
		ionic_resid_skip_lohi(&dev->inuse_qpid);
	}

	if (ionic_dbg_enable)
		dbg_ctx = ionic_api_get_debug_ctx(handle);
	else
		dbg_ctx = NULL;

	ionic_dbg_add_dev(dev, dbg_ctx);

	rc = ionic_rdma_reset_devcmd(dev);
	if (rc)
		goto err_reset;

	rc = ionic_create_rdma_admin(dev);
	if (rc)
		goto err_register;

#ifndef IONIC_HAVE_RDMA_DEV_OPS_EXT
	ibdev->owner = THIS_MODULE;
#endif
	ibdev->dev.parent = dev->hwdev;

#ifndef IONIC_HAVE_IB_REGISTER_DEVICE_NAME
	strscpy(ibdev->name, "ionic_%d", IB_DEVICE_NAME_MAX);
#endif
	strscpy(ibdev->node_desc, DEVICE_DESCRIPTION, IB_DEVICE_NODE_DESC_MAX);

	ibdev->node_type = RDMA_NODE_IB_CA;
	ibdev->phys_port_cnt = 1;

	/* the first two eq are reserved for async events */
	ibdev->num_comp_vectors = dev->eq_count - 2;

	addrconf_ifid_eui48((u8 *)&ibdev->node_guid, ndev);

#ifndef IONIC_HAVE_RDMA_DEV_OPS_EXT
	ibdev->uverbs_abi_ver = IONIC_ABI_VERSION;
#endif
	ibdev->uverbs_cmd_mask =
		BIT_ULL(IB_USER_VERBS_CMD_GET_CONTEXT)		|
		BIT_ULL(IB_USER_VERBS_CMD_QUERY_DEVICE)		|
		BIT_ULL(IB_USER_VERBS_CMD_QUERY_PORT)		|
		0;
#ifdef IONIC_HAVE_IB_UVERBS_EX_CMD_MASK
	ibdev->uverbs_ex_cmd_mask =
		0;
#endif

	ib_set_device_ops(&dev->ibdev, &ionic_dev_ops);
	ionic_datapath_setops(dev);
	ionic_controlpath_setops(dev);

	ionic_stats_init(dev);

#ifdef HAVE_REQUIRED_DMA_DEVICE
	ibdev->dma_device = ibdev->dev.parent;

#endif

#ifdef IONIC_HAVE_RDMA_SET_DEVICE_GROUP
	rdma_set_device_sysfs_group(ibdev, &ionic_rdma_attr_group);
#endif

#if defined(IONIC_HAVE_RDMA_DRIVER_ID) && !defined(IONIC_HAVE_RDMA_DEV_OPS_EXT)
	ibdev->driver_id = RDMA_DRIVER_IONIC;
#endif
#if defined(IONIC_HAVE_IB_REGISTER_DEVICE_DMA)
	rc = ib_register_device(ibdev, "ionic_%d", ibdev->dev.parent);
#elif defined(IONIC_HAVE_IB_REGISTER_DEVICE_NAME_ONLY)
	rc = ib_register_device(ibdev, "ionic_%d");
#elif defined(IONIC_HAVE_IB_REGISTER_DEVICE_NAME)
	rc = ib_register_device(ibdev, "ionic_%d", NULL);
#else
	rc = ib_register_device(ibdev, NULL);
#endif
	if (rc)
		goto err_stats;

	rc = ionic_api_set_private(handle, dev, ionic_kill_ibdev_cb,
				   IONIC_PRSN_RDMA);
	if (rc)
		goto err_api;

	ionic_dcqcn_init(dev, ident->rdma.dcqcn_profiles);

	dev->stats = kzalloc(sizeof(*dev->stats), GFP_KERNEL);
	if (dev->stats)
		dev->stats->histogram = 1;

	dev->lats = kzalloc(sizeof(*dev->lats), GFP_KERNEL);
	if (dev->lats) {
		dev->lats->histogram = 1;
		ionic_lat_init(dev->lats);
	}

	return dev;

err_api:
	ib_unregister_device(&dev->ibdev);
err_stats:
	ionic_stats_cleanup(dev);
err_register:
	ionic_kill_rdma_admin(dev, false);
	ionic_destroy_rdma_admin(dev);
err_reset:
	ionic_dbg_rm_dev(dev);
	ionic_resid_destroy(&dev->inuse_qpid);
err_qpid:
	ionic_resid_destroy(&dev->inuse_cqid);
err_cqid:
	ionic_resid_destroy(&dev->inuse_mrid);
err_mrid:
	ionic_resid_destroy(&dev->inuse_ahid);
err_ahid:
	ionic_resid_destroy(&dev->inuse_pdid);
err_pdid:
	xa_destroy(&dev->qp_tbl);
	xa_destroy(&dev->cq_tbl);
	ib_dealloc_device(ibdev);
err_dev:
	dev_put(ndev);
	return ERR_PTR(rc);
}

static int ionic_netdev_event(struct notifier_block *notifier,
			      unsigned long event, void *ptr)
{
	struct net_device *ndev = netdev_notifier_info_to_dev(ptr);
	struct ionic_ibdev *dev;
	void *handle;

	handle = ionic_get_handle_from_netdev(ndev, IONIC_API_VERSION,
					      IONIC_PRSN_RDMA);
	if (IS_ERR_OR_NULL(handle)) {
		pr_devel("unrecognized netdev %s: %d\n",
			 netdev_name(ndev), (int)PTR_ERR_OR_ZERO(handle));
		return NOTIFY_DONE;
	}

	dev = ionic_api_get_private(handle, IONIC_PRSN_RDMA);
	if (!dev) {
		netdev_dbg(ndev, "not registered\n");
		return NOTIFY_DONE;
	}

	switch (event) {
	case NETDEV_UP:
	case NETDEV_DOWN:
	case NETDEV_CHANGE:
		if (netif_running(ndev) && netif_carrier_ok(ndev))
			ionic_port_event(dev, IB_EVENT_PORT_ACTIVE);
		else
			ionic_port_event(dev, IB_EVENT_PORT_ERR);
		break;
	default:
		break;
	}

	return NOTIFY_DONE;
}

void ionic_ibdev_reset(struct ionic_ibdev *dev)
{
	struct net_device *ndev = dev->ndev;
	void *handle = dev->handle;
	int rc, reset_cnt;

	reset_cnt = ++dev->reset_cnt;
	unregister_netdevice_notifier(&dev->nb);
	ionic_destroy_ibdev(dev);

	dev = ionic_create_ibdev(handle, ndev);
	if (IS_ERR(dev)) {
		netdev_dbg(ndev, "error register ibdev %d\n", (int)PTR_ERR(dev));
		return;
	}

	dev->nb.notifier_call = ionic_netdev_event;
	rc = register_netdevice_notifier(&dev->nb);
	if (rc) {
		ionic_destroy_ibdev(dev);
		netdev_dbg(ndev, "failed to register notifier %d\n", rc);
	}

	dev->reset_cnt = reset_cnt;
}

static int ionic_aux_probe(struct auxiliary_device *adev, const struct auxiliary_device_id *id)
{
	struct ionic_aux_dev *ionic_adev = container_of(adev, struct ionic_aux_dev, adev);
	struct net_device *ndev;
	struct ionic_ibdev *dev;
	int rc;

	ndev = ionic_get_netdev_from_handle(ionic_adev->handle);
	if (IS_ERR(ndev)) {
		dev_err(&adev->dev, "Failed to get netdevice %d\n", (int)PTR_ERR(ndev));
		return PTR_ERR(ndev);
	}

	dev_put(ndev);

	dev = ionic_create_ibdev(ionic_adev->handle, ndev);
	if (IS_ERR(dev)) {
		dev_err(&adev->dev, "error register ibdev %d\n", (int)PTR_ERR(dev));
		return PTR_ERR(dev);
	}

	ibdev_info(&dev->ibdev, "registered\n");

	dev->nb.notifier_call = ionic_netdev_event;
	rc = register_netdevice_notifier(&dev->nb);
	if (rc) {
		dev_err(&adev->dev, "failed to register notifier %d\n", rc);
		ionic_destroy_ibdev(dev);
		return rc;
	}

	return 0;
}

static void ionic_aux_remove(struct auxiliary_device *adev)
{
	struct ionic_aux_dev *ionic_adev = container_of(adev, struct ionic_aux_dev, adev);
	struct ionic_ibdev *dev;

	dev = ionic_api_get_private(ionic_adev->handle, IONIC_PRSN_RDMA);
	if (!dev) {
		dev_dbg(&adev->dev, "No ibdev found\n");
		return;
	}

	unregister_netdevice_notifier(&dev->nb);

	dev_dbg(&adev->dev, "unregister ibdev\n");
	ionic_destroy_ibdev(dev);

	dev_dbg(&adev->dev, "unregistered\n");
}

static struct auxiliary_driver ionic_aux_r_driver = {
	.name = IONIC_AUX_DEVTYPE,
	.probe = ionic_aux_probe,
	.remove = ionic_aux_remove,
	.id_table = ionic_aux_id_table,
};

static int __init ionic_mod_init(void)
{
	int rc;

	pr_info("%s : %s\n", DRIVER_NAME, DRIVER_DESCRIPTION);

	ionic_evt_workq = create_workqueue(DRIVER_NAME "-evt");
	if (!ionic_evt_workq) {
		rc = -ENOMEM;
		goto err_evt_workq;
	}

	rc = ionic_dbg_init();
	if (rc)
		goto err_dbg;

	/* Register AUX Driver */
	rc = auxiliary_driver_register(&ionic_aux_r_driver);
	if (rc)
		goto err_aux;

	return 0;

err_aux:
	ionic_dbg_exit();
err_dbg:
	destroy_workqueue(ionic_evt_workq);
err_evt_workq:
	return rc;
}

static_assert(sizeof(struct ionic_v1_cqe) == 32);
static_assert(sizeof(struct ionic_v1_base_hdr) == 16);
static_assert(sizeof(struct ionic_v1_recv_bdy) == 48);
static_assert(sizeof(struct ionic_v1_common_bdy) == 48);
static_assert(sizeof(struct ionic_v1_atomic_bdy) == 48);
static_assert(sizeof(struct ionic_v1_reg_mr_bdy) == 48);
static_assert(sizeof(struct ionic_v1_bind_mw_bdy) == 48);
static_assert(sizeof(struct ionic_v1_wqe) == 64);
static_assert(sizeof(struct ionic_v1_eqe) == 4);

static void __exit ionic_mod_exit(void)
{
	auxiliary_driver_unregister(&ionic_aux_r_driver);
	destroy_workqueue(ionic_evt_workq);
	ionic_dbg_exit();
}

module_init(ionic_mod_init);
module_exit(ionic_mod_exit);
