// SPDX-License-Identifier: GPL-2.0-only
/* Copyright(c) 2022 Pensando Systems, Inc */

#include <linux/auxiliary_bus.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/vdpa.h>

#include "pds_intr.h"
#include "pds_core_if.h"
#include "pds_adminq.h"
#include "pds_auxbus.h"
#include "pds_vdpa.h"

#include "aux_drv.h"
#include "vdpa_dev.h"
#include "pci_drv.h"
#include "debugfs.h"

static const
struct auxiliary_device_id pds_vdpa_aux_id_table[] = {
	{ .name = PDS_VDPA_DEV_NAME, },
	{},
};

static void
pds_vdpa_aux_notify_handler(struct pds_auxiliary_dev *padev,
			    union pds_core_notifyq_comp *event)
{
	struct pds_vdpa_device *pdsv = padev->priv;
	struct device *dev = &padev->aux_dev.dev;
	u16 ecode = le16_to_cpu(event->ecode);

	dev_info(dev, "%s: event code %d\n", __func__, ecode);

	/* Give the upper layers a hint that something interesting
	 * may have happened.  It seems that the only thing this
	 * triggers in the virtio-net drivers above us is a check
	 * of link status.
	 *
	 * We don't set the NEEDS_RESET flag for EVENT_RESET
	 * because we're likely going through a recovery or
	 * fw_update and will be back up and running soon.
	 *
	 * TODO: testing needed to see if we need to clear DRIVER_OK
	 *       when we get a RESET_EVENT with state==0, and restore
	 *       DRIVER_OK on state==1
	 */
	if (ecode == PDS_EVENT_RESET || ecode == PDS_EVENT_LINK_CHANGE) {
		if (pdsv->hw.config_cb.callback)
			pdsv->hw.config_cb.callback(pdsv->hw.config_cb.private);
	}
}

static int
pds_vdpa_aux_probe(struct auxiliary_device *aux_dev,
		   const struct auxiliary_device_id *id)

{
	struct pds_auxiliary_dev *padev =
		container_of(aux_dev, struct pds_auxiliary_dev, aux_dev);
	struct device *dev = &aux_dev->dev;
	struct pds_vdpa_aux *vdpa_aux;
	struct pci_dev *pdev;
	struct pci_bus *bus;
	int busnr;
	u16 devfn;
	int err;

	vdpa_aux = kzalloc(sizeof(*vdpa_aux), GFP_KERNEL);
	if (!vdpa_aux)
		return -ENOMEM;

	vdpa_aux->padev = padev;
	auxiliary_set_drvdata(aux_dev, vdpa_aux);

	/* Find our VF PCI device */
	busnr = PCI_BUS_NUM(padev->id);
	devfn = padev->id & 0xff;
	bus = pci_find_bus(0, busnr);
	pdev = pci_get_slot(bus, devfn);

	vdpa_aux->vdpa_vf = pci_get_drvdata(pdev);
	vdpa_aux->vdpa_vf->vdpa_aux = vdpa_aux;
	pdev = vdpa_aux->vdpa_vf->pdev;
	if (!pds_vdpa_is_vdpa_pci_driver(pdev)) {
		dev_err(&pdev->dev, "%s: PCI driver is not pds_vdpa_pci_driver\n", __func__);
		err = -EINVAL;
		goto err_invalid_driver;
	}

	dev_info(dev, "%s: id %#04x busnr %#x devfn %#x bus %p vdpa_vf %p\n",
		 __func__, padev->id, busnr, devfn, bus, vdpa_aux->vdpa_vf);

	/* Register our PDS client with the pds_core */
	vdpa_aux->padrv.event_handler = pds_vdpa_aux_notify_handler;
	err = padev->ops->register_client(padev, &vdpa_aux->padrv);
	if (err) {
		dev_err(dev, "%s: Failed to register as client: %pe\n",
			__func__, ERR_PTR(err));
		goto err_register_client;
	}

	/* Get device ident info and set up the vdpa_mgmt_dev */
	err = pds_vdpa_get_mgmt_info(vdpa_aux);
	if (err)
		goto err_register_client;

	/* Let vdpa know that we can provide devices */
	err = vdpa_mgmtdev_register(&vdpa_aux->vdpa_mdev);
	if (err) {
		dev_err(dev, "%s: Failed to initialize vdpa_mgmt interface: %pe\n",
			__func__, ERR_PTR(err));
		goto err_mgmt_reg;
	}

	pds_vdpa_debugfs_add_ident(vdpa_aux);

	return 0;

err_mgmt_reg:
	padev->ops->unregister_client(padev);
err_register_client:
	auxiliary_set_drvdata(aux_dev, NULL);
err_invalid_driver:
	kfree(vdpa_aux);

	return err;
}

static void
pds_vdpa_aux_remove(struct auxiliary_device *aux_dev)
{
	struct pds_vdpa_aux *vdpa_aux = auxiliary_get_drvdata(aux_dev);
	struct device *dev = &aux_dev->dev;

	vdpa_mgmtdev_unregister(&vdpa_aux->vdpa_mdev);

	vdpa_aux->padev->ops->unregister_client(vdpa_aux->padev);
	if (vdpa_aux->vdpa_vf)
		pci_dev_put(vdpa_aux->vdpa_vf->pdev);

	kfree(vdpa_aux);
	auxiliary_set_drvdata(aux_dev, NULL);

	dev_info(dev, "Removed\n");
}

static struct auxiliary_driver
pds_vdpa_aux_driver = {
	.name = PDS_DEV_TYPE_VDPA_STR,
	.probe = pds_vdpa_aux_probe,
	.remove = pds_vdpa_aux_remove,
	.id_table = pds_vdpa_aux_id_table,
};

struct auxiliary_driver *
pds_vdpa_aux_driver_info(void)
{
	return &pds_vdpa_aux_driver;
}
