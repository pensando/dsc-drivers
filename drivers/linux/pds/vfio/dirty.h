// SPDX-License-Identifier: GPL-2.0-only
/* Copyright(c) 2022 Pensando Systems, Inc */

#ifndef _DIRTY_H_
#define _DIRTY_H_

#include <linux/types.h>
#include <linux/iova_bitmap.h>

#include "pds_lm.h"

struct pds_vfio_bmp_info {
	unsigned long *bmp;
	u32 bmp_bytes;
	struct pds_lm_sg_elem *sgl;
	dma_addr_t sgl_addr;
	u16 num_sge;
};

struct pds_vfio_dirty {
	struct pds_vfio_bmp_info host_seq;
	struct pds_vfio_bmp_info host_ack;
	u64 region_size;
	u64 region_start;
	u64 region_page_size;
	bool is_enabled;
};

struct pds_vfio_pci_device;

bool
pds_vfio_dirty_is_enabled(struct pds_vfio_pci_device *pds_vfio);
void
pds_vfio_dirty_set_enabled(struct pds_vfio_pci_device *pds_vfio);
void
pds_vfio_dirty_set_disabled(struct pds_vfio_pci_device *pds_vfio);
int
pds_vfio_dirty_disable(struct pds_vfio_pci_device *pds_vfio);
int
pds_vfio_dirty_enable(struct pds_vfio_pci_device *pds_vfio,
		      struct rb_root_cached *ranges, u32 nnodes,
		      u64 *page_size);
int
pds_vfio_dirty_sync(struct pds_vfio_pci_device *pds_vfio,
		    struct iova_bitmap *dirty_bitmap,
		    unsigned long iova, unsigned long length);
#endif /* _DIRTY_H_ */
