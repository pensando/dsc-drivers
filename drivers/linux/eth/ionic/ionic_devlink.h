/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2017 - 2019 Pensando Systems, Inc */

#ifndef _IONIC_DEVLINK_H_
#define _IONIC_DEVLINK_H_

#include <net/devlink.h>

/* make sure we've got a new-enough devlink support to use dev info */
#ifdef DEVLINK_INFO_VERSION_GENERIC_BOARD_ID

#define IONIC_DEVLINK

struct ionic *ionic_devlink_alloc(struct device *dev);
void ionic_devlink_free(struct ionic *ionic);
int ionic_devlink_register(struct ionic *ionic);
void ionic_devlink_unregister(struct ionic *ionic);
#else
#define ionic_devlink_alloc(dev)  devm_kzalloc(dev, sizeof(struct ionic), GFP_KERNEL)
#define ionic_devlink_free(i)     devm_kfree(i->dev, i)

#define ionic_devlink_register(x)    0
#define ionic_devlink_unregister(x)
#endif

#endif /* _IONIC_DEVLINK_H_ */
