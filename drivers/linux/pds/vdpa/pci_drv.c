// SPDX-License-Identifier: GPL-2.0-only
/* Copyright(c) 2022 Pensando Systems, Inc */

#include <linux/module.h>
#include <linux/pci.h>
#include <linux/aer.h>
#include <linux/types.h>
#include <linux/vdpa.h>

#include "pds_core_if.h"
#include "pds_vdpa.h"

#include "vdpa_dev.h"
#include "pci_drv.h"
#include "aux_drv.h"
#include "debugfs.h"

static void
pds_vdpa_dma_action(void *data)
{
	pci_free_irq_vectors((struct pci_dev *)data);
}

static int
pds_vdpa_pci_probe(struct pci_dev *pdev,
		   const struct pci_device_id *id)
{
	struct pds_vdpa_pci_device *vdpa_pdev;
	struct device *dev = &pdev->dev;
	int err;

	vdpa_pdev = kzalloc(sizeof(*vdpa_pdev), GFP_KERNEL);
	if (!vdpa_pdev)
		return -ENOMEM;
	pci_set_drvdata(pdev, vdpa_pdev);

	vdpa_pdev->pdev = pdev;
	vdpa_pdev->vf_id = pci_iov_vf_id(pdev);
	vdpa_pdev->pci_id = PCI_DEVID(pdev->bus->number, pdev->devfn);

	/* Query system for DMA addressing limitation for the device. */
	err = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(PDS_CORE_ADDR_LEN));
	if (err) {
		dev_err(dev, "Unable to obtain 64-bit DMA for consistent allocations, aborting. %pe\n",
			ERR_PTR(err));
		goto err_out_free_mem;
	}

	vdpa_pdev->vd_mdev.pci_dev = pdev;
	err = pds_vdpa_probe_virtio(&vdpa_pdev->vd_mdev);
	if (err) {
		dev_err(dev, "Unable to probe for virtio configuration: %pe\n",
			ERR_PTR(err));
		goto err_out_free_mem;
	}

	pci_enable_pcie_error_reporting(pdev);

	/* Use devres management */
	err = pcim_enable_device(pdev);
	if (err) {
		dev_err(dev, "Cannot enable PCI device: %pe\n", ERR_PTR(err));
		goto err_out_free_mem;
	}

	err = devm_add_action_or_reset(dev, pds_vdpa_dma_action, pdev);
	if (err) {
		dev_err(dev, "Failed adding devres for freeing irq vectors: %pe\n",
			ERR_PTR(err));
		goto err_out_pci_release_device;
	}

	pci_set_master(pdev);

	pds_vdpa_debugfs_add_pcidev(vdpa_pdev);

	dev_info(dev, "%s: PF %#04x VF %#04x (%d) vf_id %d domain %d vdpa_aux %p vdpa_pdev %p\n",
		 __func__, pci_dev_id(vdpa_pdev->pdev->physfn),
		 vdpa_pdev->pci_id, vdpa_pdev->pci_id, vdpa_pdev->vf_id,
		 pci_domain_nr(pdev->bus), vdpa_pdev->vdpa_aux, vdpa_pdev);

	return 0;

err_out_pci_release_device:
	pds_vdpa_remove_virtio(&vdpa_pdev->vd_mdev);
	pci_disable_pcie_error_reporting(pdev);
	pci_disable_device(pdev);
err_out_free_mem:
	kfree(vdpa_pdev);
	return err;
}

static void
pds_vdpa_pci_remove(struct pci_dev *pdev)
{
	struct pds_vdpa_pci_device *vdpa_pdev = pci_get_drvdata(pdev);

	pci_clear_master(pdev);
	pds_vdpa_remove_virtio(&vdpa_pdev->vd_mdev);
	pci_disable_pcie_error_reporting(pdev);
	pci_disable_device(pdev);
	pds_vdpa_debugfs_del_pcidev(vdpa_pdev);
	kfree(vdpa_pdev);

	dev_info(&pdev->dev, "Removed\n");
}

static const struct pci_device_id
pds_vdpa_pci_table[] = {
	{ PCI_VDEVICE(PENSANDO, PCI_DEVICE_ID_PENSANDO_VDPA_VF) },
	{ 0, }
};
MODULE_DEVICE_TABLE(pci, pds_vdpa_pci_table);

static struct pci_driver
pds_vdpa_pci_driver = {
	.name = PDS_VDPA_DRV_NAME,
	.id_table = pds_vdpa_pci_table,
	.probe = pds_vdpa_pci_probe,
	.remove = pds_vdpa_pci_remove
};

bool
pds_vdpa_is_vdpa_pci_driver(struct pci_dev *pdev)
{
	return (to_pci_driver(pdev->dev.driver) == &pds_vdpa_pci_driver);
}

static void __exit
pds_vdpa_pci_cleanup(void)
{
	auxiliary_driver_unregister(pds_vdpa_aux_driver_info());
	pci_unregister_driver(&pds_vdpa_pci_driver);

	pds_vdpa_debugfs_destroy();
}
module_exit(pds_vdpa_pci_cleanup);

static int __init
pds_vdpa_pci_init(void)
{
	int err;

	pds_vdpa_debugfs_create();

	err = pci_register_driver(&pds_vdpa_pci_driver);
	if (err) {
		pr_err("%s: pci driver register failed: %pe\n", __func__, ERR_PTR(err));
		goto err_pci;
	}

	err = auxiliary_driver_register(pds_vdpa_aux_driver_info());
	if (err) {
		pr_err("%s: aux driver register failed: %pe\n", __func__, ERR_PTR(err));
		goto err_aux;
	}

	return 0;

err_aux:
	pci_unregister_driver(&pds_vdpa_pci_driver);
err_pci:
	pds_vdpa_debugfs_destroy();
	return err;
}
module_init(pds_vdpa_pci_init);

MODULE_DESCRIPTION(PDS_VDPA_DRV_DESCRIPTION);
MODULE_AUTHOR("Pensando Systems, Inc");
MODULE_LICENSE("GPL");
