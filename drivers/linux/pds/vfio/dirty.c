// SPDX-License-Identifier: GPL-2.0-only
/* Copyright(c) 2022 Pensando Systems, Inc */

#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/io.h>
#include <linux/interval_tree.h>

#include "pds_intr.h"
#include "pds_core_if.h"
#include "pds_adminq.h"
#include "pds_auxbus.h"

#include "cmds.h"
#include "dirty.h"
#include "vfio_dev.h"
#include "trace.h"

#define READ_SEQ	true
#define WRITE_ACK	false

bool
pds_vfio_dirty_is_enabled(struct pds_vfio_pci_device *pds_vfio)
{
	return pds_vfio->dirty.is_enabled;
}

void
pds_vfio_dirty_set_enabled(struct pds_vfio_pci_device *pds_vfio)
{
	pds_vfio->dirty.is_enabled = true;
}

void
pds_vfio_dirty_set_disabled(struct pds_vfio_pci_device *pds_vfio)
{
	pds_vfio->dirty.is_enabled = false;
}

static void
pds_vfio_print_guest_region_info(struct pds_vfio_pci_device *pds_vfio,
				 u8 max_regions)
{
	int len = max_regions * sizeof(struct pds_lm_dirty_region_info);
	struct pds_lm_dirty_region_info *region_info;
	struct pci_dev *pdev = pds_vfio->pdev;
	dma_addr_t regions_dma;
	u8 num_regions;
	int err;

	region_info = kcalloc(max_regions,
			      sizeof(struct pds_lm_dirty_region_info),
			      GFP_KERNEL);
	if (!region_info)
		return;

	regions_dma = dma_map_single(pds_vfio->coredev, region_info, len,
				     DMA_FROM_DEVICE);
	if (dma_mapping_error(pds_vfio->coredev, regions_dma)) {
		kfree(region_info);
		return;
	}

	err = pds_vfio_dirty_status_cmd(pds_vfio, regions_dma,
					&max_regions, &num_regions);
	dma_unmap_single(pds_vfio->coredev, regions_dma, len, DMA_FROM_DEVICE);

	if (!err) {
		int i;

		for (i = 0; i < num_regions; i++)
			dev_dbg(&pdev->dev, "region_info[%d]: dma_base 0x%llx page_count %u page_size_log2 %u\n",
				i, le64_to_cpu(region_info[i].dma_base),
				le32_to_cpu(region_info[i].page_count),
				region_info[i].page_size_log2);
	}

	kfree(region_info);
}

static int
pds_vfio_dirty_alloc_bitmaps(struct pds_vfio_dirty *dirty,
			     u32 nbits)
{
	unsigned long *host_seq_bmp, *host_ack_bmp;

	host_seq_bmp = bitmap_zalloc(nbits, GFP_KERNEL);
	if (!host_seq_bmp)
		return -ENOMEM;

	host_ack_bmp = bitmap_zalloc(nbits, GFP_KERNEL);
	if (!host_ack_bmp) {
		bitmap_free(host_seq_bmp);
		return -ENOMEM;
	}

	dirty->host_seq.bmp = host_seq_bmp;
	dirty->host_ack.bmp = host_ack_bmp;

	return 0;
}

static void
pds_vfio_dirty_free_bitmaps(struct pds_vfio_dirty *dirty)
{
	if (dirty->host_seq.bmp)
		bitmap_free(dirty->host_seq.bmp);
	if (dirty->host_ack.bmp)
		bitmap_free(dirty->host_ack.bmp);

	dirty->host_seq.bmp = NULL;
	dirty->host_ack.bmp = NULL;
}

static void
__pds_vfio_dirty_free_sgl(struct pds_vfio_pci_device *pds_vfio,
			  struct pds_vfio_bmp_info *bmp_info)
{
	dma_free_coherent(pds_vfio->coredev,
			  bmp_info->num_sge * sizeof(*bmp_info->sgl),
			  bmp_info->sgl, bmp_info->sgl_addr);

	bmp_info->num_sge = 0;
	bmp_info->sgl = NULL;
	bmp_info->sgl_addr = 0;
}

static void
pds_vfio_dirty_free_sgl(struct pds_vfio_pci_device *pds_vfio)
{
	if (pds_vfio->dirty.host_seq.sgl)
		__pds_vfio_dirty_free_sgl(pds_vfio,
					  &pds_vfio->dirty.host_seq);
	if (pds_vfio->dirty.host_ack.sgl)
		__pds_vfio_dirty_free_sgl(pds_vfio,
					  &pds_vfio->dirty.host_ack);
}

static int
__pds_vfio_dirty_alloc_sgl(struct pds_vfio_pci_device *pds_vfio,
			   struct pds_vfio_bmp_info *bmp_info,
			   u32 page_count)
{
	struct pds_lm_sg_elem *sgl;
	dma_addr_t sgl_addr;
	u32 max_sge;

	max_sge = DIV_ROUND_UP(page_count, PAGE_SIZE * 8);

	sgl = dma_alloc_coherent(pds_vfio->coredev,
				 max_sge * sizeof(*sgl), &sgl_addr,
				 GFP_KERNEL);
	if (!sgl)
		return -ENOMEM;

	bmp_info->sgl = sgl;
	bmp_info->num_sge = max_sge;
	bmp_info->sgl_addr = sgl_addr;

	return 0;
}

static int
pds_vfio_dirty_alloc_sgl(struct pds_vfio_pci_device *pds_vfio,
			 u32 page_count)
{
	struct pds_vfio_dirty *dirty = &pds_vfio->dirty;
	int err;

	err = __pds_vfio_dirty_alloc_sgl(pds_vfio,
					 &dirty->host_seq,
					 page_count);
	if (err)
		return err;

	err = __pds_vfio_dirty_alloc_sgl(pds_vfio,
					 &dirty->host_ack,
					 page_count);
	if (err) {
		__pds_vfio_dirty_free_sgl(pds_vfio, &dirty->host_seq);
		return err;
	}

	return 0;
}

/* TODO: When pushing upstream this needs to be commonized since
 * it currently lives in drivers/vfio/pci/mlx5/cmd.c
 */
static void combine_ranges(struct rb_root_cached *root, u32 cur_nodes,
			   u32 req_nodes)
{
	struct interval_tree_node *prev, *curr, *comb_start, *comb_end;
	unsigned long min_gap;
	unsigned long curr_gap;

	/* Special shortcut when a single range is required */
	if (req_nodes == 1) {
		unsigned long last;

		comb_start = interval_tree_iter_first(root, 0, ULONG_MAX);
		curr = comb_start;
		while (curr) {
			last = curr->last;
			prev = curr;
			curr = interval_tree_iter_next(curr, 0, ULONG_MAX);
			if (prev != comb_start)
				interval_tree_remove(prev, root);
		}
		comb_start->last = last;
		return;
	}

	/* Combine ranges which have the smallest gap */
	while (cur_nodes > req_nodes) {
		prev = NULL;
		min_gap = ULONG_MAX;
		curr = interval_tree_iter_first(root, 0, ULONG_MAX);
		while (curr) {
			if (prev) {
				curr_gap = curr->start - prev->last;
				if (curr_gap < min_gap) {
					min_gap = curr_gap;
					comb_start = prev;
					comb_end = curr;
				}
			}
			prev = curr;
			curr = interval_tree_iter_next(curr, 0, ULONG_MAX);
		}
		comb_start->last = comb_end->last;
		interval_tree_remove(comb_end, root);
		cur_nodes--;
	}
}

int
pds_vfio_dirty_enable(struct pds_vfio_pci_device *pds_vfio,
		      struct rb_root_cached *ranges, u32 nnodes,
		      u64 *page_size)
{
	struct pds_vfio_dirty *dirty = &pds_vfio->dirty;
	u64 region_start, region_size, region_page_size;
	struct pds_lm_dirty_region_info *region_info;
	struct interval_tree_node *node = NULL;
	struct pci_dev *pdev = pds_vfio->pdev;
	u8 max_regions = 0, num_regions;
	dma_addr_t regions_dma = 0;
	u32 num_ranges = nnodes;
	u32 page_count;
	u16 len;
	int err;

	dev_dbg(&pdev->dev, "vf%d: Start dirty page tracking\n", pds_vfio->vf_id);

	if (pds_vfio_dirty_is_enabled(pds_vfio))
		return -EINVAL;

	pds_vfio_dirty_set_enabled(pds_vfio);

	/* find if dirty tracking is disabled, i.e. num_regions == 0 */
	err = pds_vfio_dirty_status_cmd(pds_vfio, 0, &max_regions, &num_regions);
	if (num_regions) {
		dev_err(&pdev->dev, "Dirty tracking already enabled for %d regions\n",
			num_regions);
		err = -EEXIST;
		goto err_out;
	} else if (!max_regions) {
		dev_err(&pdev->dev, "Device doesn't support dirty tracking, max_regions %d\n",
			max_regions);
		err = -EOPNOTSUPP;
		goto err_out;
	} else if (err) {
		dev_err(&pdev->dev, "Failed to get dirty status, err %pe\n",
			ERR_PTR(err));
		goto err_out;
	}

	/* Only support 1 region for now. If there are any large gaps in the
	 * VM's address regions, then this would be a waste of memory as we are
	 * generating 2 bitmaps (ack/seq) from the min address to the max
	 * address of the VM's address regions. In the future, if we support
	 * more than one region in the device/driver we can split the bitmaps
	 * on the largest address region gaps. We can do this split up to the
	 * max_regions times returned from the dirty_status command.
	 */
	max_regions = 1;
	if (num_ranges > max_regions) {
		combine_ranges(ranges, nnodes, max_regions);
		num_ranges = max_regions;
	}

	node = interval_tree_iter_first(ranges, 0, ULONG_MAX);
	if (!node) {
		err = -EINVAL;
		goto err_out;
	}

	region_size = node->last - node->start + 1;
	region_start = node->start;
	region_page_size = *page_size;

	len = sizeof(*region_info);
	region_info = kzalloc(len, GFP_KERNEL);
	if (!region_info) {
		err = -ENOMEM;
		goto err_out;
	}

	page_count = DIV_ROUND_UP(region_size, region_page_size);

	region_info->dma_base = cpu_to_le64(region_start);
	region_info->page_count = cpu_to_le32(page_count);
	region_info->page_size_log2 = ilog2(region_page_size);

	regions_dma = dma_map_single(pds_vfio->coredev, (void *)region_info, len,
				     DMA_BIDIRECTIONAL);
	if (dma_mapping_error(pds_vfio->coredev, regions_dma)) {
		err = -ENOMEM;
		kfree(region_info);
		goto err_out;
	}

	err = pds_vfio_dirty_enable_cmd(pds_vfio, regions_dma, max_regions);
	dma_unmap_single(pds_vfio->coredev, regions_dma, len, DMA_BIDIRECTIONAL);
	/* page_count might be adjusted by the device,
	 * update it before freeing region_info DMA
	 */
	page_count = le32_to_cpu(region_info->page_count);

	dev_dbg(&pdev->dev, "region_info: regions_dma 0x%llx dma_base 0x%llx page_count %u page_size_log2 %u\n",
		regions_dma, region_start, page_count, (u8)ilog2(region_page_size));

	kfree(region_info);
	if (err)
		goto err_out;

	err = pds_vfio_dirty_alloc_bitmaps(dirty, page_count);
	if (err) {
		dev_err(&pdev->dev, "Failed to alloc dirty bitmaps: %pe\n",
			ERR_PTR(err));
		goto err_out;
	}

	err = pds_vfio_dirty_alloc_sgl(pds_vfio, page_count);
	if (err) {
		dev_err(&pdev->dev, "Failed to alloc dirty sg lists: %pe\n",
			ERR_PTR(err));
		goto err_free_bitmaps;
	}

	dirty->region_start = region_start;
	dirty->region_size = region_size;
	dirty->region_page_size = region_page_size;

	pds_vfio_print_guest_region_info(pds_vfio, max_regions);

	return 0;

err_free_bitmaps:
	pds_vfio_dirty_free_bitmaps(dirty);
err_out:
	pds_vfio_dirty_set_disabled(pds_vfio);
	return err;
}

int
pds_vfio_dirty_disable(struct pds_vfio_pci_device *pds_vfio)
{
	int err;

	if (!pds_vfio_dirty_is_enabled(pds_vfio))
		return 0;

	pds_vfio_dirty_set_disabled(pds_vfio);
	err = pds_vfio_dirty_disable_cmd(pds_vfio);
	pds_vfio_dirty_free_sgl(pds_vfio);
	pds_vfio_dirty_free_bitmaps(&pds_vfio->dirty);

	return err;
}

static int
pds_vfio_dirty_seq_ack(struct pds_vfio_pci_device *pds_vfio,
		       struct pds_vfio_bmp_info *bmp_info,
		       u32 offset, u32 bmp_bytes,
		       bool read_seq)
{
	const char *bmp_type_str = read_seq ? "read_seq" : "write_ack";
	struct pci_dev *pdev = pds_vfio->pdev;
	int bytes_remaining;
	dma_addr_t bmp_dma;
	u8 dma_direction;
	u16 num_sge = 0;
	int err, i;
	u64 *bmp;

	bmp = (u64 *)((u64)bmp_info->bmp + offset);

	dma_direction = read_seq ? DMA_FROM_DEVICE : DMA_TO_DEVICE;
	bmp_dma = dma_map_single(pds_vfio->coredev, bmp, bmp_bytes,
				 dma_direction);
	if (dma_mapping_error(pds_vfio->coredev, bmp_dma))
		return -EINVAL;

	bytes_remaining = bmp_bytes;

	for (i = 0; i < bmp_info->num_sge && bytes_remaining > 0; i++) {
		struct pds_lm_sg_elem *sg_elem = &bmp_info->sgl[i];
		u32 len = (bytes_remaining > PAGE_SIZE) ?
			PAGE_SIZE : bytes_remaining;

		sg_elem->addr = cpu_to_le64(bmp_dma + i * PAGE_SIZE);
		sg_elem->len = cpu_to_le32(len);

		bytes_remaining -= len;
		++num_sge;
	}

	err = pds_vfio_dirty_seq_ack_cmd(pds_vfio, bmp_info->sgl_addr,
					 num_sge, offset, bmp_bytes, read_seq);
	if (err)
		dev_err(&pdev->dev, "Dirty bitmap %s failed offset %u bmp_bytes %u num_sge %u DMA 0x%llx: %pe\n",
			bmp_type_str, offset, bmp_bytes, num_sge, bmp_info->sgl_addr, ERR_PTR(err));

	dma_unmap_single(pds_vfio->coredev, bmp_dma, bmp_bytes, dma_direction);

	return err;
}

static int
pds_vfio_dirty_write_ack(struct pds_vfio_pci_device *pds_vfio, u32 offset,
			 u32 len)
{
	return pds_vfio_dirty_seq_ack(pds_vfio,
				      &pds_vfio->dirty.host_ack, offset,
				      len, WRITE_ACK);
}

static int
pds_vfio_dirty_read_seq(struct pds_vfio_pci_device *pds_vfio, u32 offset,
			u32 len)
{
	return pds_vfio_dirty_seq_ack(pds_vfio,
					  &pds_vfio->dirty.host_seq, offset,
					  len, READ_SEQ);
}

static int
pds_vfio_dirty_process_bitmaps(struct pds_vfio_pci_device *pds_vfio,
			       struct iova_bitmap *dirty_bitmap, u32 bmp_offset,
			       u32 len_bytes)
{
	u64 page_size = pds_vfio->dirty.region_page_size;
	u64 region_start = pds_vfio->dirty.region_start;
	u32 bmp_offset_bit;
	int dword_count, i;
	u64 *seq, *ack;

	dword_count = len_bytes / 8;
	seq = (u64 *)((u64)pds_vfio->dirty.host_seq.bmp + bmp_offset);
	ack = (u64 *)((u64)pds_vfio->dirty.host_ack.bmp + bmp_offset);
	bmp_offset_bit = bmp_offset * 8;

	for (i = 0; i < dword_count; i++) {
		u64 xor = le64_to_cpu(seq[i]) ^ le64_to_cpu(ack[i]);
		u8 bit_i;

		/* prepare for next write_ack call */
		ack[i] = seq[i];

		for (bit_i = 0; bit_i < BITS_PER_U64; ++bit_i) {
			if (xor & BIT(bit_i)) {
				u64 abs_bit_i = bmp_offset_bit + i * 64 + bit_i;
				u64 addr = abs_bit_i * page_size + region_start;

				iova_bitmap_set(dirty_bitmap, addr, page_size);
			}
		}

		if (xor) {
			trace_xor_bits(&pds_vfio->pdev->dev, bmp_offset_bit,
				       i, xor);
			trace_xor_addresses(&pds_vfio->pdev->dev,
					    region_start,
					    page_size,
					    bmp_offset_bit, i, xor);
		}
	}

	return 0;
}

int
pds_vfio_dirty_sync(struct pds_vfio_pci_device *pds_vfio,
		    struct iova_bitmap *dirty_bitmap,
		    unsigned long iova, unsigned long length)
{
	struct pds_vfio_dirty *dirty = &pds_vfio->dirty;
	struct pci_dev *pdev = pds_vfio->pdev;
	u64 bmp_offset, bmp_bytes;
	u64 bitmap_size, pages;
	int err;

	dev_dbg(&pdev->dev, "vf%d: Get dirty page bitmap\n", pds_vfio->vf_id);

	if (!pds_vfio_dirty_is_enabled(pds_vfio)) {
		dev_err(&pdev->dev, "vf%d: Sync failed, dirty tracking is disabled\n",
			pds_vfio->vf_id);
		return -EINVAL;
	}

	pages = DIV_ROUND_UP(length, pds_vfio->dirty.region_page_size);
	bitmap_size = round_up(pages, sizeof(__u64) * BITS_PER_BYTE) /
		BITS_PER_BYTE;

	dev_dbg(&pdev->dev, "vf%d: iova 0x%lx length %lu page_size %llu pages %llu bitmap_size %llu\n",
		pds_vfio->vf_id, iova, length,
		pds_vfio->dirty.region_page_size, pages, bitmap_size);

	if (!length ||
	    ((dirty->region_start + iova + length) >
	     (dirty->region_start + dirty->region_size))) {
		dev_err(&pdev->dev, "Invalid iova 0x%lx and/or length 0x%lx to sync\n",
			iova, length);
		return -EINVAL;
	}

	/* bitmap is modified in 64 bit chunks */
	bmp_bytes = ALIGN(DIV_ROUND_UP(length / dirty->region_page_size, 8), 8);
	if (bmp_bytes != bitmap_size) {
		dev_err(&pdev->dev, "Calculated bitmap bytes %llu not equal to bitmap size %llu\n",
			bmp_bytes, bitmap_size);
		return -EINVAL;
	}

	bmp_offset = DIV_ROUND_UP(iova / dirty->region_page_size, 8);

	dev_dbg(&pdev->dev, "Syncing dirty bitmap, iova 0x%lx length 0x%lx, bmp_offset %llu bmp_bytes %llu\n",
		iova, length, bmp_offset, bmp_bytes);

	err = pds_vfio_dirty_read_seq(pds_vfio, bmp_offset, bmp_bytes);
	if (err)
		return err;

	err = pds_vfio_dirty_process_bitmaps(pds_vfio, dirty_bitmap,
					     bmp_offset, bmp_bytes);
	if (err)
		return err;

	err = pds_vfio_dirty_write_ack(pds_vfio, bmp_offset, bmp_bytes);
	if (err)
		return err;

	return 0;
}
