/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2017 - 2022 Pensando Systems, Inc */

#ifndef _PDS_VDPA_DEBUGFS_H_
#define _PDS_VDPA_DEBUGFS_H_

#include <linux/debugfs.h>


#ifdef CONFIG_DEBUG_FS

void pds_vdpa_debugfs_create(void);
void pds_vdpa_debugfs_destroy(void);
void pds_vdpa_debugfs_add_pcidev(struct pds_vdpa_pci_device *vdpa_pdev);
void pds_vdpa_debugfs_del_pcidev(struct pds_vdpa_pci_device *vdpa_pdev);
void pds_vdpa_debugfs_add_ident(struct pds_vdpa_aux *vdpa_aux);
void pds_vdpa_debugfs_add_vdpadev(struct pds_vdpa_device *pdsv);
void pds_vdpa_debugfs_del_vdpadev(struct pds_vdpa_device *pdsv);
#else
static inline void pds_vdpa_debugfs_create(void) { }
static inline void pds_vdpa_debugfs_destroy(void) { }
static inline void pds_vdpa_debugfs_add_pcidev(struct pds_vdpa_pci_device *vdpa_pdev) { }
static inline void pds_vdpa_debugfs_del_pcidev(struct pds_vdpa_pci_device *vdpa_pdev) { }
static inline void pds_vdpa_debugfs_add_ident(struct pds_vdpa_aux *vdpa_aux) { }
static inline void pds_vdpa_debugfs_add_vdpadev(struct pds_vdpa_device *pdsv) { }
static inline void pds_vdpa_debugfs_del_vdpadev(struct pds_vdpa_device *pdsv) { }
#endif

#endif /* _PDS_VDPA_DEBUGFS_H_ */
