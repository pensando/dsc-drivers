// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2018-2020 Pensando Systems, Inc.  All rights reserved.
 */

#include <linux/dma-mapping.h>

#include "ionic_fw.h"
#include "ionic_ibdev.h"

static int ionic_v1_stat_normalize(struct ionic_v1_stat *hw_stats, int hw_stats_count)
{
	struct ionic_v1_stat *stat;
	int hw_stat_i;

	for (hw_stat_i = 0; hw_stat_i < hw_stats_count; ++hw_stat_i) {
		stat = &hw_stats[hw_stat_i];

		stat->type_off = be32_to_cpu(stat->be_type_off);
		stat->name[sizeof(stat->name) - 1] = 0;
		if (ionic_v1_stat_type(stat) == IONIC_V1_STAT_TYPE_NONE)
			break;
	}

	return hw_stat_i;
}

#ifdef IONIC_HAVE_IB_HW_STAT_DESC
static void ionic_fill_stats_desc(struct rdma_stat_desc *hw_stats_hdrs,
				  struct ionic_v1_stat *hw_stats, int hw_stats_count)
#else
static void ionic_fill_stats_desc(const char **hw_stats_hdrs,
				  struct ionic_v1_stat *hw_stats, int hw_stats_count)
#endif
{
	struct ionic_v1_stat *stat;
	int hw_stat_i;

	for (hw_stat_i = 0; hw_stat_i < hw_stats_count; ++hw_stat_i) {
		stat = &hw_stats[hw_stat_i];
#ifdef IONIC_HAVE_IB_HW_STAT_DESC
		hw_stats_hdrs[hw_stat_i].name = stat->name;
#else
		hw_stats_hdrs[hw_stat_i] = stat->name;
#endif
	}
}

static u64 ionic_v1_stat_val(struct ionic_v1_stat *stat,
			     void *vals_buf, size_t vals_len)
{
	int type = ionic_v1_stat_type(stat);
	unsigned int off = ionic_v1_stat_off(stat);

#define __ionic_v1_stat_validate(__type)		\
	((off + sizeof(__type) <= vals_len) &&		\
	 (IS_ALIGNED(off, sizeof(__type))))

	switch (type) {
	case IONIC_V1_STAT_TYPE_8:
		if (__ionic_v1_stat_validate(u8))
			return *(u8 *)(vals_buf + off);
		break;
	case IONIC_V1_STAT_TYPE_LE16:
		if (__ionic_v1_stat_validate(__le16))
			return le16_to_cpu(*(__le16 *)(vals_buf + off));
		break;
	case IONIC_V1_STAT_TYPE_LE32:
		if (__ionic_v1_stat_validate(__le32))
			return le32_to_cpu(*(__le32 *)(vals_buf + off));
		break;
	case IONIC_V1_STAT_TYPE_LE64:
		if (__ionic_v1_stat_validate(__le64))
			return le64_to_cpu(*(__le64 *)(vals_buf + off));
		break;
	case IONIC_V1_STAT_TYPE_BE16:
		if (__ionic_v1_stat_validate(__be16))
			return be16_to_cpu(*(__be16 *)(vals_buf + off));
		break;
	case IONIC_V1_STAT_TYPE_BE32:
		if (__ionic_v1_stat_validate(__be32))
			return be32_to_cpu(*(__be32 *)(vals_buf + off));
		break;
	case IONIC_V1_STAT_TYPE_BE64:
		if (__ionic_v1_stat_validate(__be64))
			return be64_to_cpu(*(__be64 *)(vals_buf + off));
		break;
	}

	return ~0ull;
#undef __ionic_v1_stat_validate
}

static int ionic_hw_stats_cmd(struct ionic_ibdev *dev,
			      dma_addr_t dma, size_t len, int qid, int op)
{
	struct ionic_admin_wr wr = {
		.work = COMPLETION_INITIALIZER_ONSTACK(wr.work),
		.wqe = {
			.op = op,
			.id_ver = cpu_to_le32(qid),
			.stats = {
				.dma_addr = cpu_to_le64(dma),
				.length = cpu_to_le32(len),
			}
		}
	};

	if (dev->admin_opcodes <= op)
		return -ENOSYS;

	ionic_admin_post(dev, &wr);

	return ionic_admin_wait(dev, &wr, IONIC_ADMIN_F_INTERRUPT);
}

static int ionic_init_hw_stats(struct ionic_ibdev *dev)
{
	dma_addr_t hw_stats_dma;
	int rc, hw_stats_count;

	if (dev->hw_stats_hdrs)
		return 0;

	dev->hw_stats_count = 0;

	/* buffer for current values from the device */
	dev->hw_stats_buf = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!dev->hw_stats_buf) {
		rc = -ENOMEM;
		goto err_buf;
	}

	/* buffer for names, sizes, offsets of values */
	dev->hw_stats = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!dev->hw_stats) {
		rc = -ENOMEM;
		goto err_hw_stats;
	}

	/* request the names, sizes, offsets */
	hw_stats_dma = dma_map_single(dev->hwdev, dev->hw_stats,
				      PAGE_SIZE, DMA_FROM_DEVICE);
	rc = dma_mapping_error(dev->hwdev, hw_stats_dma);
	if (rc)
		goto err_dma;

	rc = ionic_hw_stats_cmd(dev, hw_stats_dma, PAGE_SIZE, 0, IONIC_V1_ADMIN_STATS_HDRS);
	if (rc)
		goto err_cmd;

	dma_unmap_single(dev->hwdev, hw_stats_dma, PAGE_SIZE, DMA_FROM_DEVICE);

	/* normalize and count the number of hw_stats */
	hw_stats_count = ionic_v1_stat_normalize(dev->hw_stats, PAGE_SIZE / sizeof(*dev->hw_stats));
	if (!hw_stats_count) {
		rc = -ENODATA;
		goto err_dma;
	}

	dev->hw_stats_count = hw_stats_count;

	/* alloc and init array of names, for alloc_hw_stats */
	dev->hw_stats_hdrs = kcalloc(hw_stats_count,
				     sizeof(*dev->hw_stats_hdrs),
				     GFP_KERNEL);
	if (!dev->hw_stats_hdrs) {
		rc = -ENOMEM;
		goto err_dma;
	}

	ionic_fill_stats_desc(dev->hw_stats_hdrs, dev->hw_stats, hw_stats_count);

	return 0;

err_cmd:
	dma_unmap_single(dev->hwdev, hw_stats_dma, PAGE_SIZE, DMA_FROM_DEVICE);
err_dma:
	kfree(dev->hw_stats);
err_hw_stats:
	kfree(dev->hw_stats_buf);
err_buf:
	dev->hw_stats_count = 0;
	dev->hw_stats = NULL;
	dev->hw_stats_buf = NULL;
	dev->hw_stats_hdrs = NULL;
	return rc;
}

#ifdef IONIC_HAVE_IB_PORT_U32
static struct rdma_hw_stats *ionic_alloc_hw_stats(struct ib_device *ibdev,
						  u32 port)
#else
static struct rdma_hw_stats *ionic_alloc_hw_stats(struct ib_device *ibdev,
						  u8 port)
#endif
{
	struct ionic_ibdev *dev = to_ionic_ibdev(ibdev);

	if (port != 1)
		return NULL;

	return rdma_alloc_hw_stats_struct(dev->hw_stats_hdrs,
					  dev->hw_stats_count,
					  RDMA_HW_STATS_DEFAULT_LIFESPAN);
}

#ifdef IONIC_HAVE_IB_PORT_U32
static int ionic_get_hw_stats(struct ib_device *ibdev,
			      struct rdma_hw_stats *hw_stats,
			      u32 port, int index)
#else
static int ionic_get_hw_stats(struct ib_device *ibdev,
			      struct rdma_hw_stats *hw_stats,
			      u8 port, int index)
#endif
{
	struct ionic_ibdev *dev = to_ionic_ibdev(ibdev);
	dma_addr_t hw_stats_dma;
	int rc, hw_stat_i;

	if (port != 1)
		return -EINVAL;

	hw_stats_dma = dma_map_single(dev->hwdev, dev->hw_stats_buf,
				      PAGE_SIZE, DMA_FROM_DEVICE);
	rc = dma_mapping_error(dev->hwdev, hw_stats_dma);
	if (rc)
		goto err_dma;

	rc = ionic_hw_stats_cmd(dev, hw_stats_dma, PAGE_SIZE, 0, IONIC_V1_ADMIN_STATS_VALS);
	if (rc)
		goto err_cmd;

	dma_unmap_single(dev->hwdev, hw_stats_dma,
			 PAGE_SIZE, DMA_FROM_DEVICE);

	for (hw_stat_i = 0; hw_stat_i < dev->hw_stats_count; ++hw_stat_i)
		hw_stats->value[hw_stat_i] =
			ionic_v1_stat_val(&dev->hw_stats[hw_stat_i],
					  dev->hw_stats_buf, PAGE_SIZE);

	return hw_stat_i;

err_cmd:
	dma_unmap_single(dev->hwdev, hw_stats_dma,
			 PAGE_SIZE, DMA_FROM_DEVICE);
err_dma:
	return rc;
}

static struct rdma_hw_stats *
ionic_counter_alloc_stats(struct rdma_counter *counter)
{
	struct ionic_ibdev *dev = to_ionic_ibdev(counter->device);
	struct ionic_counter *ionic_counter;
	int err;

	ionic_counter = kzalloc(sizeof(*ionic_counter), GFP_KERNEL);
	if (!ionic_counter)
		return NULL;

	/* buffer for current values from the device */
	ionic_counter->vals = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!ionic_counter->vals)
		goto err_vals;

	err = xa_alloc(&dev->counter_stats->xa_counters, &counter->id, ionic_counter,
		       XA_LIMIT(0, IONIC_MAX_QPID), GFP_KERNEL);
	if (err)
		goto err_xa;

	INIT_LIST_HEAD(&ionic_counter->qp_list);

	return rdma_alloc_hw_stats_struct(dev->counter_stats->stats_hdrs,
					 dev->counter_stats->queue_stats_count,
					 RDMA_HW_STATS_DEFAULT_LIFESPAN);
err_xa:
	kfree(ionic_counter->vals);
err_vals:
	kfree(ionic_counter);

	return NULL;
}

static int ionic_counter_dealloc(struct rdma_counter *counter)
{
	struct ionic_ibdev *dev = to_ionic_ibdev(counter->device);
	struct ionic_counter *ionic_counter;

	ionic_counter = (struct ionic_counter *)xa_erase(&dev->counter_stats->xa_counters,
							 counter->id);
	if (!ionic_counter)
		return -EINVAL;

	kfree(ionic_counter->vals);
	kfree(ionic_counter);

	return 0;
}

static int ionic_counter_bind_qp(struct rdma_counter *counter, struct ib_qp *qp)
{
	struct ionic_ibdev *dev = to_ionic_ibdev(counter->device);
	struct ionic_qp *ionic_qp = to_ionic_qp(qp);
	struct ionic_counter *ionic_counter;

	ionic_counter = (struct ionic_counter *)xa_load(&dev->counter_stats->xa_counters,
							counter->id);
	if (!ionic_counter)
		return -EINVAL;

	list_add_tail(&ionic_qp->qp_list_counter, &ionic_counter->qp_list);
	qp->counter = counter;

	return 0;
}

static int ionic_counter_unbind_qp(struct ib_qp *qp)
{
	struct ionic_qp *ionic_qp = to_ionic_qp(qp);

	if (qp->counter) {
		list_del(&ionic_qp->qp_list_counter);
		qp->counter = NULL;
	}

	return 0;
}

static int ionic_get_qp_stats(struct ib_device *ibdev,
			      struct rdma_hw_stats *hw_stats,
			      u32 counter_id)
{
	struct ionic_ibdev *dev = to_ionic_ibdev(ibdev);
	struct ionic_counter *ionic_counter = NULL;
	struct ionic_qp *ionic_qp = NULL;
	dma_addr_t hw_stats_dma;
	int rc, hw_stat_i = 0;

	ionic_counter = (struct ionic_counter *)xa_load(&dev->counter_stats->xa_counters,
							 counter_id);
	if (!ionic_counter)
		return -EINVAL;

	hw_stats_dma = dma_map_single(dev->hwdev, ionic_counter->vals, PAGE_SIZE, DMA_FROM_DEVICE);
	rc = dma_mapping_error(dev->hwdev, hw_stats_dma);
	if (rc)
		return rc;

	memset(hw_stats->value, 0, sizeof(u64) * hw_stats->num_counters);

	list_for_each_entry(ionic_qp, &ionic_counter->qp_list, qp_list_counter) {
		rc = ionic_hw_stats_cmd(dev, hw_stats_dma, PAGE_SIZE, ionic_qp->qpid,
					IONIC_V1_ADMIN_QP_STATS_VALS);
		if (rc)
			goto err_cmd;

		for (hw_stat_i = 0; hw_stat_i < dev->counter_stats->queue_stats_count; ++hw_stat_i)
			hw_stats->value[hw_stat_i] +=
				ionic_v1_stat_val(&dev->counter_stats->hdr[hw_stat_i],
						  ionic_counter->vals, PAGE_SIZE);
	}

	dma_unmap_single(dev->hwdev, hw_stats_dma, PAGE_SIZE, DMA_FROM_DEVICE);
	return hw_stat_i;

err_cmd:
	dma_unmap_single(dev->hwdev, hw_stats_dma, PAGE_SIZE, DMA_FROM_DEVICE);

	return rc;
}

static int ionic_counter_update_stats(struct rdma_counter *counter)
{
	return ionic_get_qp_stats(counter->device, counter->stats, counter->id);
}

static int ionic_alloc_counters(struct ionic_ibdev *dev)
{
	int rc, hw_stats_count;
	dma_addr_t hdr_dma;

	/* buffer for names, sizes, offsets of values */
	dev->counter_stats->hdr = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!dev->counter_stats->hdr)
		return -ENOMEM;

	hdr_dma = dma_map_single(dev->hwdev, dev->counter_stats->hdr, PAGE_SIZE, DMA_FROM_DEVICE);
	rc = dma_mapping_error(dev->hwdev, hdr_dma);
	if (rc)
		goto err_dma;

	rc = ionic_hw_stats_cmd(dev, hdr_dma, PAGE_SIZE, 0, IONIC_V1_ADMIN_QP_STATS_HDRS);
	if (rc)
		goto err_cmd;

	dma_unmap_single(dev->hwdev, hdr_dma, PAGE_SIZE, DMA_FROM_DEVICE);

	/* normalize and count the number of hw_stats */
	hw_stats_count = ionic_v1_stat_normalize(dev->counter_stats->hdr,
						 PAGE_SIZE / sizeof(*dev->counter_stats->hdr));
	if (!hw_stats_count) {
		rc = -ENODATA;
		goto err_dma;
	}

	dev->counter_stats->queue_stats_count = hw_stats_count;

	/* alloc and init array of names */
	dev->counter_stats->stats_hdrs = kcalloc(hw_stats_count,
						 sizeof(*dev->counter_stats->stats_hdrs),
						 GFP_KERNEL);
	if (!dev->counter_stats->stats_hdrs) {
		rc = -ENOMEM;
		goto err_dma;
	}

	ionic_fill_stats_desc(dev->counter_stats->stats_hdrs,
			      dev->counter_stats->hdr, hw_stats_count);

	return 0;

err_cmd:
	dma_unmap_single(dev->hwdev, hdr_dma, PAGE_SIZE, DMA_FROM_DEVICE);
err_dma:
	kfree(dev->counter_stats->hdr);

	return rc;
}

static const struct ib_device_ops ionic_hw_stats_ops = {
#ifdef IONIC_HAVE_RDMA_DEV_OPS_EXT
	.driver_id		= RDMA_DRIVER_IONIC,
#endif
#ifdef IONIC_HAVE_IB_HW_PORT_STATS
	.alloc_hw_port_stats	= ionic_alloc_hw_stats,
#else
	.alloc_hw_stats		= ionic_alloc_hw_stats,
#endif
	.get_hw_stats		= ionic_get_hw_stats,
};

static const struct ib_device_ops ionic_counter_stats_ops = {
	.counter_alloc_stats	= ionic_counter_alloc_stats,
	.counter_dealloc		= ionic_counter_dealloc,
	.counter_bind_qp		= ionic_counter_bind_qp,
	.counter_unbind_qp		= ionic_counter_unbind_qp,
	.counter_update_stats	= ionic_counter_update_stats,
};

void ionic_stats_init(struct ionic_ibdev *dev)
{
	int rc;

	rc = ionic_init_hw_stats(dev);
	if (rc)
		netdev_dbg(dev->ndev, "ionic_rdma: Failed to init hw stats\n");
	else
		ib_set_device_ops(&dev->ibdev, &ionic_hw_stats_ops);

	dev->counter_stats = kzalloc(sizeof(*dev->counter_stats), GFP_KERNEL);
	if (!dev->counter_stats)
		return;

	rc = ionic_alloc_counters(dev);
	if (rc) {
		netdev_dbg(dev->ndev, "ionic_rdma: Failed to init counter stats\n");
		kfree(dev->counter_stats);
		dev->counter_stats = NULL;
		return;
	}

	xa_init_flags(&dev->counter_stats->xa_counters, XA_FLAGS_ALLOC);

	ib_set_device_ops(&dev->ibdev, &ionic_counter_stats_ops);
}

void ionic_stats_cleanup(struct ionic_ibdev *dev)
{
	if (dev->counter_stats) {
		xa_destroy(&dev->counter_stats->xa_counters);
		kfree(dev->counter_stats->hdr);
		kfree(dev->counter_stats->stats_hdrs);
		kfree(dev->counter_stats);
		dev->counter_stats = NULL;
	}

	kfree(dev->hw_stats);
	kfree(dev->hw_stats_buf);
	kfree(dev->hw_stats_hdrs);
}
