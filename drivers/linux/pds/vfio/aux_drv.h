// SPDX-License-Identifier: GPL-2.0-only
/* Copyright(c) 2022 Pensando Systems, Inc */

#ifndef _AUX_DRV_H_
#define _AUX_DRV_H_

#include <linux/auxiliary_bus.h>
#include <linux/interrupt.h>
#include <linux/io.h>

#include "pds_intr.h"
#include "pds_adminq.h"
#include "pds_auxbus.h"

struct pds_vfio_pci_device;

struct pds_vfio_aux {
	struct pds_auxiliary_dev *padev;
	struct pds_auxiliary_drv padrv;
	struct pds_vfio_pci_device *pds_vfio;
	struct work_struct work;
};

struct auxiliary_driver *
pds_vfio_aux_driver_info(void);
struct pds_vfio_aux *
pds_vfio_aux_get_drvdata(int vf_pci_id);
void
pds_vfio_put_aux_dev(struct pds_vfio_aux *vfio_aux);

#endif /* _AUX_DRV_H_ */
