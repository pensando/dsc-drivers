/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright(c) 2022 Pensando Systems, Inc */

#ifndef _VDPA_DEV_H_
#define _VDPA_DEV_H_

#include <linux/pci.h>
#include <linux/vdpa.h>


struct pds_vdpa_aux;

struct pds_vdpa_vq_info {
	bool ready;
	u64 desc_addr;
	u64 avail_addr;
	u64 used_addr;
	u32 q_len;
	u16 qid;

	void __iomem *notify;
	dma_addr_t notify_pa;

	u64 doorbell;
	u16 avail_idx;
	u16 used_idx;
	int intr_index;

	u8 hw_qtype;
	u16 hw_qindex;

	struct vdpa_callback event_cb;
	struct pds_vdpa_device *pdsv;
};

#define PDS_VDPA_MAX_QUEUES	65
#define PDS_VDPA_MAX_QLEN	32768
struct pds_vdpa_hw {
	/* TODO make dynamic when we add support for MQ and CtrlQ */
	struct pds_vdpa_vq_info vqs[PDS_VDPA_MAX_QUEUES];
	u64 req_features;		/* features requested by vdpa */
	u64 actual_features;		/* features negotiated and in use */
	u8 vdpa_index;			/* rsvd for future subdevice use */
	u8 num_vqs;			/* num vqs in use */
	u16 status;			/* vdpa status */
	struct vdpa_callback config_cb;
};

struct pds_vdpa_device {
	struct vdpa_device vdpa_dev;
	struct pds_vdpa_aux *vdpa_aux;
	struct pds_vdpa_hw hw;

	struct virtio_net_config vn_config;
	dma_addr_t vn_config_pa;
	struct dentry *dentry;
};

int pds_vdpa_get_mgmt_info(struct pds_vdpa_aux *vdpa_aux);

#endif /* _VDPA_DEV_H_ */
