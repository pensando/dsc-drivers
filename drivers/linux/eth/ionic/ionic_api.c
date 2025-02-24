// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2017 - 2022 Pensando Systems, Inc. All rights reserved. */

#include <linux/kernel.h>

#include "ionic.h"
#include "ionic_bus.h"
#include "ionic_dev.h"
#include "ionic_lif.h"
#include "ionic_txrx.h"

struct net_device *ionic_get_netdev_from_handle(void *handle)
{
	struct ionic_lif *lif = handle;

	if (!lif)
		return ERR_PTR(-ENXIO);

	dev_hold(lif->netdev);

	return lif->netdev;
}
EXPORT_SYMBOL_GPL(ionic_get_netdev_from_handle);

void *ionic_get_handle_from_netdev(struct net_device *netdev,
				   const char *api_version,
				   enum ionic_api_prsn prsn)
{
	struct ionic_lif *lif;

	if (strcmp(api_version, IONIC_API_VERSION))
		return ERR_PTR(-EINVAL);

	lif = ionic_netdev_lif(netdev);
	if (!lif || !lif->nrdma_eqs)
		return ERR_PTR(-ENXIO);

	/* TODO: Rework if supporting more than one child */
	if (lif->child_lif_cfg.prsn != IONIC_PRSN_NONE &&
	    lif->child_lif_cfg.prsn != prsn)
		return ERR_PTR(-EBUSY);

	return lif;
}
EXPORT_SYMBOL_GPL(ionic_get_handle_from_netdev);

bool ionic_api_stay_registered(void *handle)
{
	/* TODO: Implement when eth driver reset is implemented */
	return false;
}
EXPORT_SYMBOL_GPL(ionic_api_stay_registered);

void ionic_api_request_reset(void *handle)
{
	struct ionic_lif *lif = handle;
	struct ionic *ionic;
	int err;

	union ionic_dev_cmd cmd = {
		.cmd.opcode = IONIC_CMD_RDMA_RESET_LIF,
		.cmd.lif_index = cpu_to_le16(lif->child_lif_cfg.index),
	};

	ionic = lif->ionic;

	mutex_lock(&ionic->dev_cmd_lock);

	ionic_dev_cmd_go(&ionic->idev, &cmd);
	err = ionic_dev_cmd_wait(ionic, devcmd_timeout);

	mutex_unlock(&ionic->dev_cmd_lock);

	if (err) {
		netdev_warn(lif->netdev, "request_reset: error %d\n", err);
	}

	if (lif->child_lif_cfg.priv &&
	    lif->child_lif_cfg.reset_cb)
		(*lif->child_lif_cfg.reset_cb)(lif->child_lif_cfg.priv);
}
EXPORT_SYMBOL_GPL(ionic_api_request_reset);

void *ionic_api_get_private(void *handle, enum ionic_api_prsn prsn)
{
	struct ionic_lif *lif = handle;

	if (lif->child_lif_cfg.prsn != prsn)
		return NULL;

	return lif->child_lif_cfg.priv;
}
EXPORT_SYMBOL_GPL(ionic_api_get_private);

int ionic_api_set_private(void *handle, void *priv,
			  void (*reset_cb)(void *priv),
			  enum ionic_api_prsn prsn)
{
	struct ionic_lif *lif = handle;
	struct ionic_lif_cfg *cfg;

	cfg = &lif->child_lif_cfg;
	if (priv && cfg->priv)
		return -EBUSY;

	cfg->priv = priv;
	cfg->prsn = prsn;
	cfg->reset_cb = reset_cb;

	return 0;
}
EXPORT_SYMBOL_GPL(ionic_api_set_private);

struct device *ionic_api_get_device(void *handle)
{
	struct ionic_lif *lif = handle;

	return lif->netdev->dev.parent;
}
EXPORT_SYMBOL_GPL(ionic_api_get_device);

const struct ionic_devinfo *ionic_api_get_devinfo(void *handle)
{
	struct ionic_lif *lif = handle;

	return &lif->ionic->idev.dev_info;
}
EXPORT_SYMBOL_GPL(ionic_api_get_devinfo);

struct dentry *ionic_api_get_debug_ctx(void *handle)
{
	struct ionic_lif *lif = handle;

	return lif->dentry;
}
EXPORT_SYMBOL_GPL(ionic_api_get_debug_ctx);

const union ionic_lif_identity *ionic_api_get_identity(void *handle,
						       int *lif_index)
{
	struct ionic_lif *lif = handle;

	if (lif_index)
		*lif_index = lif->child_lif_cfg.index;

	/* TODO: Do all LIFs have the same ident? */
	return &lif->ionic->ident.lif;
}
EXPORT_SYMBOL_GPL(ionic_api_get_identity);

/* queuetype support level */
static const u8 ionic_qtype_versions[IONIC_QTYPE_MAX] = {
	[IONIC_QTYPE_ADMINQ]  = 0,   /* 0 = Base version with CQ support */
	[IONIC_QTYPE_NOTIFYQ] = 0,   /* 0 = Base version */
	[IONIC_QTYPE_RXQ]     = 2,   /* 0 = Base version with CQ+SG support
				      * 1 =       ... with EQ
				      * 2 =       ... with CMB rings
				      */
	[IONIC_QTYPE_TXQ]     = 3,   /* 0 = Base version with CQ+SG support
				      * 1 =   ... with Tx SG version 1
				      * 2 =       ... with EQ
				      * 3 =       ... with CMB rings
				      */
};

struct ionic_qtype_info ionic_api_get_queue_identity(void *handle, int qtype)
{
	union ionic_q_identity __iomem *q_ident;
	struct ionic_lif *lif = handle;
	struct ionic_qtype_info qti;
	struct ionic_dev *idev;
	struct ionic *ionic;
	int err;

	union ionic_dev_cmd cmd = {
		.q_identify.opcode = IONIC_CMD_Q_IDENTIFY,
		.q_identify.lif_type = cpu_to_le16(lif->lif_type),
		.q_identify.type = qtype,
		.q_identify.ver = ionic_qtype_versions[qtype],
	};

	ionic = lif->ionic;
	idev = &lif->ionic->idev;
	q_ident = (union ionic_q_identity __iomem *)&idev->dev_cmd_regs->data;

	mutex_lock(&ionic->dev_cmd_lock);

	ionic_dev_cmd_go(&ionic->idev, &cmd);
	err = ionic_dev_cmd_wait(ionic, devcmd_timeout);

	if (err)
		netdev_warn(lif->netdev, "get_queue_identity: error %d\n", err);

	qti.version   = ioread8(&q_ident->version);
	qti.supported = ioread8(&q_ident->supported);
	qti.features  = readq(&q_ident->features);
	qti.desc_sz   = ioread16(&q_ident->desc_sz);
	qti.comp_sz   = ioread16(&q_ident->comp_sz);
	qti.sg_desc_sz   = ioread16(&q_ident->sg_desc_sz);
	qti.max_sg_elems = ioread16(&q_ident->max_sg_elems);
	qti.sg_desc_stride = ioread16(&q_ident->sg_desc_stride);

	mutex_unlock(&ionic->dev_cmd_lock);

	return qti;
}
EXPORT_SYMBOL_GPL(ionic_api_get_queue_identity);

u8 ionic_api_get_expdb(void *handle)
{
	struct ionic_lif *lif = handle;
	u8 ret = 0;

	if (lif->ionic->idev.phy_cmb_expdb64_pages)
		ret |= IONIC_EXPDB_64B_WQE;
	if (lif->ionic->idev.phy_cmb_expdb128_pages)
		ret |= IONIC_EXPDB_128B_WQE;
	if (lif->ionic->idev.phy_cmb_expdb256_pages)
		ret |= IONIC_EXPDB_256B_WQE;
	if (lif->ionic->idev.phy_cmb_expdb512_pages)
		ret |= IONIC_EXPDB_512B_WQE;

	return ret;
}
EXPORT_SYMBOL_GPL(ionic_api_get_expdb);

int ionic_api_get_intr(void *handle, int *irq)
{
	struct ionic_intr_info *intr_obj;
	struct ionic_lif *lif = handle;
	int err;

	if (!lif->nrdma_eqs_avail)
		return -ENOSPC;

	intr_obj = kzalloc(sizeof(*intr_obj), GFP_KERNEL);
	if (!intr_obj)
		return -ENOSPC;

	err = ionic_intr_alloc(lif->ionic, intr_obj);
	if (err)
		goto done;

	err = ionic_bus_get_irq(lif->ionic, intr_obj->index);
	if (err < 0) {
		ionic_intr_free(lif->ionic, intr_obj->index);
		goto done;
	}

	lif->nrdma_eqs_avail--;

	*irq = err;
	err = intr_obj->index;
done:
	kfree(intr_obj);
	return err;
}
EXPORT_SYMBOL_GPL(ionic_api_get_intr);

void ionic_api_put_intr(void *handle, int intr)
{
	struct ionic_lif *lif = handle;

	ionic_intr_free(lif->ionic, intr);

	lif->nrdma_eqs_avail++;
}
EXPORT_SYMBOL_GPL(ionic_api_put_intr);

int ionic_api_get_cmb(void *handle, u32 *pgid, phys_addr_t *pgaddr, int order,
		      u8 stride_log2, bool *expdb)
{
	struct ionic_lif *lif = handle;

	return ionic_get_cmb(lif, pgid, pgaddr, order, stride_log2, expdb);
}
EXPORT_SYMBOL_GPL(ionic_api_get_cmb);

void ionic_api_put_cmb(void *handle, u32 pgid, int order)
{
	struct ionic_lif *lif = handle;

	ionic_put_cmb(lif, pgid, order);
}
EXPORT_SYMBOL_GPL(ionic_api_put_cmb);

void ionic_api_kernel_dbpage(void *handle,
			     struct ionic_intr __iomem **intr_ctrl,
			     u32 *dbid, u64 __iomem **dbpage)
{
	struct ionic_lif *lif = handle;

	*intr_ctrl = lif->ionic->idev.intr_ctrl;

	*dbid = lif->kern_pid;
	*dbpage = lif->kern_dbpage;
}
EXPORT_SYMBOL_GPL(ionic_api_kernel_dbpage);

int ionic_api_get_dbid(void *handle, u32 *dbid, phys_addr_t *addr)
{
	struct ionic_lif *lif = handle;
	int id, dbpage_num;


	if (ionic_bus_dbpage_per_pid(lif->ionic)) {
		mutex_lock(&lif->dbid_inuse_lock);

		if (!lif->dbid_inuse) {
			mutex_unlock(&lif->dbid_inuse_lock);
			return -EINVAL;
		}

		id = find_first_zero_bit(lif->dbid_inuse, lif->dbid_count);
		if (id == lif->dbid_count) {
			mutex_unlock(&lif->dbid_inuse_lock);
			return -ENOMEM;
		}

		set_bit(id, lif->dbid_inuse);

		mutex_unlock(&lif->dbid_inuse_lock);

		dbpage_num = ionic_db_page_num(lif, id);
	} else {
		id = 0;
		dbpage_num = 0;
	}

	*dbid = id;
	*addr = ionic_bus_phys_dbpage(lif->ionic, dbpage_num);

	return 0;
}
EXPORT_SYMBOL_GPL(ionic_api_get_dbid);

void ionic_api_put_dbid(void *handle, int dbid)
{
	struct ionic_lif *lif = handle;

	if (ionic_bus_dbpage_per_pid(lif->ionic)) {
		mutex_lock(&lif->dbid_inuse_lock);
		if (lif->dbid_inuse)
			clear_bit(dbid, lif->dbid_inuse);
		mutex_unlock(&lif->dbid_inuse_lock);
	}
}
EXPORT_SYMBOL_GPL(ionic_api_put_dbid);

int ionic_api_adminq_post(void *handle, struct ionic_admin_ctx *ctx)
{
	struct ionic_lif *lif = handle;

	return ionic_adminq_post(lif, ctx);
}
EXPORT_SYMBOL_GPL(ionic_api_adminq_post);

int ionic_api_adminq_post_wait(void *handle, struct ionic_admin_ctx *ctx)
{
	struct ionic_lif *lif = handle;

	return ionic_adminq_post_wait(lif, ctx);
}
EXPORT_SYMBOL_GPL(ionic_api_adminq_post_wait);
