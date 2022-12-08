// SPDX-License-Identifier: GPL-2.0-only
/* Copyright(c) 2022 Pensando Systems, Inc */

#ifndef _VFIO_DEV_H_
#define _VFIO_DEV_H_

#include <linux/pci.h>
#include <linux/vfio_pci_core.h>

#include "dirty.h"
#include "lm.h"

struct pds_vfio_aux;

struct pds_vfio_pci_device {
	struct vfio_pci_core_device vfio_coredev;
	struct pci_dev *pdev;
	struct pds_vfio_aux *vfio_aux;
	struct device *coredev;

	struct pds_vfio_lm_file *save_file;
	struct pds_vfio_lm_file *restore_file;
	struct pds_vfio_dirty dirty;
	struct mutex state_mutex; /* protect migration state */
	enum vfio_device_mig_state state;
	spinlock_t reset_lock; /* protect reset_done flow */
	u8 deferred_reset;
	enum vfio_device_mig_state deferred_reset_state;

	int vf_id;
	int pci_id;
};

const struct vfio_device_ops *
pds_vfio_ops_info(void);
void
pds_vfio_state_mutex_unlock(struct pds_vfio_pci_device *pds_vfio);
struct pds_vfio_pci_device *
pds_vfio_pci_drvdata(struct pci_dev *pdev);
void
pds_vfio_reset(struct pds_vfio_pci_device *pds_vfio);
void
pds_vfio_deferred_reset(struct pds_vfio_pci_device *pds_vfio,
			enum vfio_device_mig_state reset_state);

#endif /* _VFIO_DEV_H_ */
