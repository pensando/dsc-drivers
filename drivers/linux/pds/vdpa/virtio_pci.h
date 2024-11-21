/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright(c) 2023 Advanced Micro Devices, Inc */

#ifndef _PDS_VIRTIO_PCI_H_
#define _PDS_VIRTIO_PCI_H_
int pds_vdpa_probe_virtio(struct virtio_pci_modern_device *mdev);
void pds_vdpa_remove_virtio(struct virtio_pci_modern_device *mdev);
#endif /* _PDS_VIRTIO_PCI_H_ */
