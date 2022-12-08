/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright(c) 2022 Pensando Systems, Inc */

#ifndef _PCI_DRV_H
#define _PCI_DRV_H

#include <linux/pci.h>
#include <linux/virtio_pci_modern.h>

#define PDS_VDPA_DRV_NAME           "pds_vdpa"
#define PDS_VDPA_DRV_DESCRIPTION    "Pensando vDPA VF Device Driver"

#define PDS_VDPA_BAR_BASE	0
#define PDS_VDPA_BAR_INTR	2
#define PDS_VDPA_BAR_DBELL	4

struct pds_dev_bar {
	int           index;
	void __iomem  *vaddr;
	phys_addr_t   pa;
	unsigned long len;
};

struct pds_vdpa_intr_info {
	int index;
	int irq;
	int qid;
	char name[32];
};

struct pds_vdpa_pci_device {
	struct pci_dev *pdev;
	struct pds_vdpa_aux *vdpa_aux;

	int vf_id;
	int pci_id;

	int nintrs;
	struct pds_vdpa_intr_info *intrs;

	struct dentry *dentry;

	struct virtio_pci_modern_device vd_mdev;
};

bool pds_vdpa_is_vdpa_pci_driver(struct pci_dev *pdev);

int pds_vdpa_probe_virtio(struct virtio_pci_modern_device *mdev);
void pds_vdpa_remove_virtio(struct virtio_pci_modern_device *mdev);

#endif /* _PCI_DRV_H */
