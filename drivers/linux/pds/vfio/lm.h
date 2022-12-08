// SPDX-License-Identifier: GPL-2.0-only
/* Copyright(c) 2022 Pensando Systems, Inc */

#ifndef _LM_H_
#define _LM_H_

#include <linux/fs.h>
#include <linux/mutex.h>
#include <linux/scatterlist.h>
#include <linux/types.h>
#include <linux/vfio.h>

#include "pds_lm.h"

struct pds_vfio_lm_file {
	struct file *filep;
	struct mutex lock; /* protect live migration data file */
	u64 size; /* Size with valid data */
	u64 alloc_size; /* Total allocated size. Always >= len */
	struct page **pages; /* Backing pages for file */
	unsigned long long npages;
	struct sg_table sg_table; /* SG table for backing pages */
	struct pds_lm_sg_elem *sgl; /* DMA mapping */
	dma_addr_t sgl_addr;
	u16 num_sge;
	struct scatterlist *last_offset_sg; /* Iterator */
	unsigned int sg_last_entry;
	unsigned long last_offset;
};

struct pds_vfio_pci_device;

struct file *
pds_vfio_step_device_state_locked(struct pds_vfio_pci_device *pds_vfio,
				  enum vfio_device_mig_state next);
int
pds_vfio_dma_logging_report(struct vfio_device *vdev, unsigned long iova,
			    unsigned long length,
			    struct iova_bitmap *dirty);
int
pds_vfio_dma_logging_start(struct vfio_device *vdev,
			   struct rb_root_cached *ranges, u32 nnodes,
			   u64 *page_size);
int
pds_vfio_dma_logging_stop(struct vfio_device *vdev);
const char *
pds_vfio_lm_state(enum vfio_device_mig_state state);
void
pds_vfio_put_save_file(struct pds_vfio_pci_device *pds_vfio);
void
pds_vfio_put_restore_file(struct pds_vfio_pci_device *pds_vfio);

#endif /* _LM_H_ */
