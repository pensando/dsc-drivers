/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright(c) 2022 Pensando Systems, Inc */

#ifndef _AUX_DRV_H_
#define _AUX_DRV_H_

#include <linux/auxiliary_bus.h>
#include <linux/interrupt.h>
#include <linux/io.h>

#include "pds_intr.h"
#include "pds_adminq.h"
#include "pds_auxbus.h"

struct pds_vdpa_pci_device;

struct pds_vdpa_aux {
	struct pds_auxiliary_dev *padev;
	struct pds_auxiliary_drv padrv;

	struct pds_vdpa_pci_device *vdpa_vf;
	struct vdpa_mgmt_dev vdpa_mdev;
	struct pds_vdpa_device *pdsv;

	struct pds_vdpa_ident ident;
	bool local_mac_bit;
};

struct auxiliary_driver *
pds_vdpa_aux_driver_info(void);

#endif /* _AUX_DRV_H_ */
