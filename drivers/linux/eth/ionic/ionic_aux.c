// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2023-2024, Advanced Micro Devices, Inc. */

#include <linux/kernel.h>
#include "ionic.h"
#include "ionic_lif.h"
#include "ionic_aux.h"

static DEFINE_IDA(aux_ida);

static void ionic_auxbus_release(struct device *dev)
{
	/* Dummy function for aux bus registration */
}

int ionic_auxbus_register(struct ionic_lif *lif)
{
	struct ionic_aux_dev *ionic_adev;
	struct auxiliary_device *aux_dev;
	int rc, id;

	if (!lif->ionic->nrdma_eqs_per_lif)
		return 0;

	ionic_adev = kzalloc(sizeof(*ionic_adev), GFP_KERNEL);
	if (!ionic_adev)
		return -ENOMEM;

	aux_dev = &ionic_adev->adev;

	id = ida_alloc_range(&aux_ida, 0, INT_MAX, GFP_KERNEL);
	if (id < 0) {
		dev_err(lif->ionic->dev, "Failed to allocate aux id: %d, aborting\n", id);
		rc = id;
		goto err_adev_free;
	}

	aux_dev->id = id;
	aux_dev->name = IONIC_AUX_DEVTYPE;
	aux_dev->dev.parent = &lif->ionic->pdev->dev;
	aux_dev->dev.release = ionic_auxbus_release;
	ionic_adev->handle = lif;
	rc = auxiliary_device_init(aux_dev);
	if (rc) {
		dev_err(lif->ionic->dev, "Failed to initialize aux device: %d, aborting\n", rc);
		goto err_ida_free;
	}

	rc = auxiliary_device_add(aux_dev);
	if (rc) {
		dev_err(lif->ionic->dev, "Failed to add auxiliary device: %d, aborting\n", rc);
		goto err_aux_uninit;
	}

	lif->ionic_adev = ionic_adev;

	return rc;
err_aux_uninit:
	auxiliary_device_uninit(aux_dev);
err_ida_free:
	ida_free(&aux_ida, id);
err_adev_free:
	kfree(ionic_adev);

	return rc;
}

void ionic_auxbus_unregister(struct ionic_lif *lif)
{
	struct auxiliary_device *aux_dev;

	mutex_lock(&lif->adev_lock);
	if (!lif->ionic_adev)
		goto out;

	aux_dev = &lif->ionic_adev->adev;

	auxiliary_device_delete(aux_dev);
	ida_free(&aux_ida, aux_dev->id);
	auxiliary_device_uninit(aux_dev);

	kfree(lif->ionic_adev);
	lif->ionic_adev = NULL;

out:
	mutex_unlock(&lif->adev_lock);
}
