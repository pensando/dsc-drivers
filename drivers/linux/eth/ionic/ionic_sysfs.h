/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Advanced Micro Devices, Inc */

#ifndef _IONIC_SYSFS_H
#define _IONIC_SYSFS_H

#include "ionic_lif.h"

#ifdef CONFIG_SYSFS
void ionic_lif_set_mgmt_nic_sysfs_group(struct ionic_lif *lif);
#else
static inline void ionic_lif_set_mgmt_nic_sysfs_group(struct ionic_lif *lif) { }
#endif

#endif /* _IONIC_SYSFS_H */
