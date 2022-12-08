// SPDX-License-Identifier: GPL-2.0-only
/* Copyright(c) 2022 Pensando Systems, Inc */

#include <linux/module.h>
#include <linux/pci.h>
#include <linux/types.h>
#include <linux/vfio.h>

#include "pds_core_if.h"
#include "vfio_dev.h"
#include "aux_drv.h"

#define PDS_VFIO_DRV_NAME           "pds_vfio"
#define PDS_VFIO_DRV_DESCRIPTION    "Pensando VFIO Device Driver"

// TODO: When pushing upstream add to include/linux/pci_ids.h
#define PCI_VENDOR_ID_PENSANDO		0x1dd8

static int
pds_vfio_pci_probe(struct pci_dev *pdev,
		   const struct pci_device_id *id)
{
	struct pds_vfio_pci_device *pds_vfio;
	int err;

	pds_vfio = vfio_alloc_device(pds_vfio_pci_device, vfio_coredev.vdev,
				     &pdev->dev,  pds_vfio_ops_info());
	if (IS_ERR(pds_vfio))
		return PTR_ERR(pds_vfio);

	dev_set_drvdata(&pdev->dev, &pds_vfio->vfio_coredev);
	pds_vfio->pdev = pdev;

	err = vfio_pci_core_register_device(&pds_vfio->vfio_coredev);
	if (err)
		goto out_put_vdev;

	return 0;

out_put_vdev:
	vfio_put_device(&pds_vfio->vfio_coredev.vdev);
	return err;
}

static void
pds_vfio_pci_remove(struct pci_dev *pdev)
{
	struct pds_vfio_pci_device *pds_vfio = pds_vfio_pci_drvdata(pdev);

	dev_info(&pdev->dev, "remove");

	vfio_pci_core_unregister_device(&pds_vfio->vfio_coredev);
	vfio_put_device(&pds_vfio->vfio_coredev.vdev);
}

static const struct pci_device_id
pds_vfio_pci_table[] = {
	{
		.class = PCI_CLASS_STORAGE_EXPRESS,
		.class_mask = 0xffffff,
		.vendor = PCI_VENDOR_ID_PENSANDO,
		.device = PCI_DEVICE_ID_PENSANDO_NVME_VF,
		.subvendor = PCI_ANY_ID,
		.subdevice = PCI_ANY_ID,
		.override_only = PCI_ID_F_VFIO_DRIVER_OVERRIDE,
	},
	{ 0, }
};
MODULE_DEVICE_TABLE(pci, pds_vfio_pci_table);

static void
pds_vfio_pci_aer_reset_done(struct pci_dev *pdev)
{
	struct pds_vfio_pci_device *pds_vfio = pds_vfio_pci_drvdata(pdev);

	pds_vfio_reset(pds_vfio);
}

static const struct
pci_error_handlers pds_vfio_pci_err_handlers = {
	.reset_done = pds_vfio_pci_aer_reset_done,
	.error_detected = vfio_pci_core_aer_err_detected,
};

static struct pci_driver
pds_vfio_pci_driver = {
	.name = PDS_VFIO_DRV_NAME,
	.id_table = pds_vfio_pci_table,
	.probe = pds_vfio_pci_probe,
	.remove = pds_vfio_pci_remove,
	.err_handler = &pds_vfio_pci_err_handlers,
	.driver_managed_dma = true,
};

bool
pds_vfio_is_vfio_pci_driver(struct pci_dev *pdev)
{
	return (to_pci_driver(pdev->dev.driver) == &pds_vfio_pci_driver);
}

static void __exit
pds_vfio_pci_cleanup(void)
{
	auxiliary_driver_unregister(pds_vfio_aux_driver_info());

	pci_unregister_driver(&pds_vfio_pci_driver);
}
module_exit(pds_vfio_pci_cleanup);

static int __init
pds_vfio_pci_init(void)
{
	int err;

	err = pci_register_driver(&pds_vfio_pci_driver);
	if (err) {
		pr_err("pci driver register failed: %pe\n", ERR_PTR(err));
		return err;
	}

	err = auxiliary_driver_register(pds_vfio_aux_driver_info());
	if (err) {
		pr_err("aux driver register failed: %pe\n", ERR_PTR(err));
		pci_unregister_driver(&pds_vfio_pci_driver);
		return err;
	}

	return 0;
}
module_init(pds_vfio_pci_init);

MODULE_DESCRIPTION(PDS_VFIO_DRV_DESCRIPTION);
MODULE_AUTHOR("Pensando Systems, Inc");
MODULE_LICENSE("GPL");
MODULE_INFO(supported, "external");
