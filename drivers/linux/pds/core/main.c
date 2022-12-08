// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2022 Pensando Systems, Inc */

/* main PCI driver and mgmt logic */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/pci.h>
#include <linux/aer.h>

#include "core.h"

MODULE_DESCRIPTION(PDSC_DRV_DESCRIPTION);
MODULE_AUTHOR("Pensando Systems, Inc");
MODULE_LICENSE("GPL");

/* Supported devices */
static const struct pci_device_id pdsc_id_table[] = {
	{ PCI_VDEVICE(PENSANDO, PCI_DEVICE_ID_PENSANDO_CORE_PF) },
	{ 0, }	/* end of table */
};
MODULE_DEVICE_TABLE(pci, pdsc_id_table);

void pdsc_queue_health_check(struct pdsc *pdsc)
{
	unsigned long mask;

	/* Don't do a check when in a transition state */
	mask = BIT_ULL(PDSC_S_INITING_DRIVER) |
	       BIT_ULL(PDSC_S_STOPPING_DRIVER);
	if (pdsc->state & mask)
		return;

	/* Queue a new health check if one isn't already queued */
	queue_work(pdsc->wq, &pdsc->health_work);
}

static void pdsc_wdtimer_cb(struct timer_list *t)
{
	struct pdsc *pdsc = from_timer(pdsc, t, wdtimer);

	dev_dbg(pdsc->dev, "%s: jiffies %ld\n", __func__, jiffies);
	mod_timer(&pdsc->wdtimer,
		  round_jiffies(jiffies + pdsc->wdtimer_period));

	pdsc_queue_health_check(pdsc);
}

static void pdsc_unmap_bars(struct pdsc *pdsc)
{
	struct pdsc_dev_bar *bars = pdsc->bars;
	unsigned int i;

	for (i = 0; i < PDS_CORE_BARS_MAX; i++) {
		if (bars[i].vaddr) {
			pcim_iounmap(pdsc->pdev, bars[i].vaddr);
			bars[i].vaddr = NULL;
		}

		bars[i].len = 0;
		bars[i].bus_addr = 0;
		bars[i].res_index = 0;
	}
}

static int pdsc_map_bars(struct pdsc *pdsc)
{
	struct pdsc_dev_bar *bar = pdsc->bars;
	struct pci_dev *pdev = pdsc->pdev;
	struct device *dev = pdsc->dev;
	struct pdsc_dev_bar *bars;
	unsigned int i, j;
	int err = 0;
	u32 sig;

	bars = pdsc->bars;
	pdsc->num_bars = 0;

	/* Since the PCI interface in the hardware is configurable,
	 * we need to poke into all the bars to find the set we're
	 * expecting.  The will be in the right order.
	 */
	for (i = 0, j = 0; i < PDS_CORE_BARS_MAX; i++) {
		if (!(pci_resource_flags(pdev, i) & IORESOURCE_MEM))
			continue;

		bars[j].len = pci_resource_len(pdev, i);
		bars[j].bus_addr = pci_resource_start(pdev, i);
		bars[j].res_index = i;

		/* only map the whole bar 0 */
		if (j > 0) {
			bars[j].vaddr = NULL;
		} else {
			bars[j].vaddr = pcim_iomap(pdev, i, bars[j].len);
			if (!bars[j].vaddr) {
				dev_err(dev,
					"Cannot memory-map BAR %d, aborting\n",
					i);
				return -ENODEV;
			}
		}

		j++;
	}
	pdsc->num_bars = j;

	/* BAR0: dev_cmd and interrupts */
	if (pdsc->num_bars < 1) {
		dev_err(dev, "No bars found\n");
		err = -EFAULT;
		goto err_out;
	}

	if (bar->len < PDS_CORE_BAR0_SIZE) {
		dev_err(dev, "Resource bar size %lu too small\n",
			bar->len);
		err = -EFAULT;
		goto err_out;
	}

	pdsc->info_regs = bar->vaddr + PDS_CORE_BAR0_DEV_INFO_REGS_OFFSET;
	pdsc->cmd_regs = bar->vaddr + PDS_CORE_BAR0_DEV_CMD_REGS_OFFSET;
	pdsc->intr_status = bar->vaddr + PDS_CORE_BAR0_INTR_STATUS_OFFSET;
	pdsc->intr_ctrl = bar->vaddr + PDS_CORE_BAR0_INTR_CTRL_OFFSET;

	sig = ioread32(&pdsc->info_regs->signature);
	if (sig != PDS_CORE_DEV_INFO_SIGNATURE) {
		dev_err(dev, "Incompatible firmware signature %x", sig);
		err = -EFAULT;
		goto err_out;
	}

	/* BAR1: doorbells */
	bar++;
	if (pdsc->num_bars < 2) {
		dev_err(dev, "Doorbell bar missing\n");
		err = -EFAULT;
		goto err_out;
	}

	pdsc->db_pages = bar->vaddr;
	pdsc->phy_db_pages = bar->bus_addr;

	return 0;

err_out:
	pdsc_unmap_bars(pdsc);
	pdsc->info_regs = 0;
	pdsc->cmd_regs = 0;
	pdsc->intr_status = 0;
	pdsc->intr_ctrl = 0;
	return err;
}

void __iomem *pdsc_map_dbpage(struct pdsc *pdsc, int page_num)
{
	return pci_iomap_range(pdsc->pdev,
			       pdsc->bars[PDS_CORE_PCI_BAR_DBELL].res_index,
			       (u64)page_num << PAGE_SHIFT, PAGE_SIZE);
}

static int pdsc_sriov_configure(struct pci_dev *pdev, int num_vfs)
{
	struct pds_core_vf_setattr_cmd vfc = { .attr = PDS_CORE_VF_ATTR_STATSADDR };
	struct pdsc *pdsc = pci_get_drvdata(pdev);
	struct device *dev = pdsc->dev;
	enum pds_core_vif_types vt;
	bool enabled = false;
	struct pdsc_vf *v;
	int ret = 0;
	int i;

	if (num_vfs > 0) {

		pdsc->vfs = kcalloc(num_vfs, sizeof(struct pdsc_vf), GFP_KERNEL);
		if (!pdsc->vfs)
			return -ENOMEM;
		pdsc->num_vfs = num_vfs;

		for (i = 0; i < num_vfs; i++) {
			v = &pdsc->vfs[i];
			v->stats_pa = dma_map_single(pdsc->dev, &v->stats,
						     sizeof(v->stats), DMA_FROM_DEVICE);
			if (dma_mapping_error(pdsc->dev, v->stats_pa)) {
				dev_err(pdsc->dev, "DMA mapping failed for vf[%d] stats\n", i);
				v->stats_pa = 0;
			} else {
				vfc.stats.len = cpu_to_le32(sizeof(v->stats));
				vfc.stats.pa = cpu_to_le64(v->stats_pa);
				(void)pdsc_set_vf_config(pdsc, i, &vfc);
			}
		}

		ret = pci_enable_sriov(pdev, num_vfs);
		if (ret) {
			dev_err(dev, "Cannot enable SRIOV: %pe\n", ERR_PTR(ret));
			goto no_vfs;
		}

		/* If any VF types are enabled, start the VF aux devices */
		for (vt = 0; vt < PDS_DEV_TYPE_MAX && !enabled; vt++)
			enabled = pdsc->viftype_status[vt].max_devs &&
				  pdsc->viftype_status[vt].enabled;
		if (enabled)
			for (i = 0; i < num_vfs; i++)
				pdsc_auxbus_dev_add_vf(pdsc, i);

		return num_vfs;
	}

	i = pci_num_vf(pdev);
	while (i--)
		pdsc_auxbus_dev_del_vf(pdsc, i);

no_vfs:
	pci_disable_sriov(pdev);

	for (i = pdsc->num_vfs - 1; i >= 0; i--) {
		v = &pdsc->vfs[i];

		if (v->stats_pa) {
			vfc.stats.len = 0;
			vfc.stats.pa = 0;
			(void)pdsc_set_vf_config(pdsc, i, &vfc);
			dma_unmap_single(pdsc->dev, v->stats_pa,
					 sizeof(v->stats), DMA_FROM_DEVICE);
			v->stats_pa = 0;
		}
	}

	kfree(pdsc->vfs);
	pdsc->vfs = NULL;
	pdsc->num_vfs = 0;

	return ret;
}

DEFINE_IDA(pdsc_pf_ida);

//#define PDSC_WQ_NAME_LEN sizeof(((struct workqueue_struct *)0ULL)->name)
#define PDSC_WQ_NAME_LEN 24

static int pdsc_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	struct device *dev = &pdev->dev;
	char wq_name[PDSC_WQ_NAME_LEN];
	struct pdsc *pdsc;
	int err = 0;

	pdsc = pdsc_dl_alloc(dev);
	if (!pdsc)
		return -ENOMEM;

	pdsc->pdev = pdev;
	pdsc->dev = &pdev->dev;
	set_bit(PDSC_S_FW_DEAD, &pdsc->state);
	set_bit(PDSC_S_INITING_DRIVER, &pdsc->state);
	pci_set_drvdata(pdev, pdsc);
	pdsc_debugfs_add_dev(pdsc);

	err = ida_alloc(&pdsc_pf_ida, GFP_KERNEL);
	if (err < 0) {
		dev_err(pdsc->dev, "%s: id alloc failed, %pe\n", __func__, ERR_PTR(err));
		goto err_out_free_devlink;
	}
	pdsc->id = err;

	/* Query system for DMA addressing limitation for the device. */
	err = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(PDS_CORE_ADDR_LEN));
	if (err) {
		dev_err(dev, "Unable to obtain 64-bit DMA for consistent allocations, aborting. %pe\n",
			ERR_PTR(err));
		goto err_out_free_devlink;
	}

	pci_enable_pcie_error_reporting(pdev);

	/* Use devres management */
	err = pcim_enable_device(pdev);
	if (err) {
		dev_err(dev, "Cannot enable PCI device: %pe\n", ERR_PTR(err));
		goto err_out_free_devlink;
	}

	err = pci_request_regions(pdev, PDS_CORE_DRV_NAME);
	if (err) {
		dev_err(dev, "Cannot request PCI regions: %pe\n", ERR_PTR(err));
		goto err_out_pci_disable_device;
	}

	pcie_print_link_status(pdev);
	pci_set_master(pdev);

	err = pdsc_map_bars(pdsc);
	if (err)
		goto err_out_pci_disable_device;

	/* General workqueue and timer, but don't start timer yet */
	snprintf(wq_name, sizeof(wq_name), "%s.%d", PDS_CORE_DRV_NAME, pdsc->id);
	pdsc->wq = create_singlethread_workqueue(wq_name);
	INIT_WORK(&pdsc->health_work, pdsc_health_thread);
	timer_setup(&pdsc->wdtimer, pdsc_wdtimer_cb, 0);
	pdsc->wdtimer_period = PDSC_WATCHDOG_SECS * HZ;

	/* PDS device setup */
	mutex_init(&pdsc->devcmd_lock);
	mutex_init(&pdsc->config_lock);
	spin_lock_init(&pdsc->adminq_lock);

	mutex_lock(&pdsc->config_lock);
	init_rwsem(&pdsc->vf_op_lock);
	err = pdsc_setup(pdsc, PDSC_SETUP_INIT);
	if (err)
		goto err_out_unmap_bars;
	err = pdsc_start(pdsc);
	if (err)
		goto err_out_teardown;

	/* publish devlink device */
	err = pdsc_dl_register(pdsc);
	if (err) {
		dev_err(dev, "Cannot register devlink: %pe\n", ERR_PTR(err));
		goto err_out;
	}

	mutex_unlock(&pdsc->config_lock);

	pdsc->fw_generation = PDS_CORE_FW_STS_F_GENERATION &
			      ioread8(&pdsc->info_regs->fw_status);
	/* Lastly, start the health check timer */
	mod_timer(&pdsc->wdtimer, round_jiffies(jiffies + pdsc->wdtimer_period));

	clear_bit(PDSC_S_INITING_DRIVER, &pdsc->state);
	return 0;

err_out:
	pdsc_stop(pdsc);
err_out_teardown:
	pdsc_teardown(pdsc, true, PDSC_TEARDOWN_REMOVING);
	pci_free_irq_vectors(pdev);
err_out_unmap_bars:
	del_timer_sync(&pdsc->wdtimer);
	if (pdsc->wq) {
		flush_workqueue(pdsc->wq);
		destroy_workqueue(pdsc->wq);
		pdsc->wq = NULL;
	}
	mutex_unlock(&pdsc->config_lock);
	mutex_destroy(&pdsc->config_lock);
	mutex_destroy(&pdsc->devcmd_lock);
	pci_clear_master(pdev);
	pdsc_unmap_bars(pdsc);
	pci_release_regions(pdev);
err_out_pci_disable_device:
	pci_disable_pcie_error_reporting(pdev);
	pci_disable_device(pdev);
err_out_free_devlink:
	ida_free(&pdsc_pf_ida, pdsc->id);
	pdsc_debugfs_del_dev(pdsc);
	pdsc_dl_free(pdsc);

	return err;
}

static void pdsc_remove(struct pci_dev *pdev)
{
	struct pdsc *pdsc = pci_get_drvdata(pdev);
	enum pds_core_vif_types vt;

	/* Undo the devlink registration now to be sure there
	 * are no requests while we're stopping.
	 */
	pdsc_dl_unregister(pdsc);

	/* Remove the aux_bus connections before other cleanup
	 * so that the clients can use the AdminQ to cleanly
	 * shut themselves down.
	 */
	pdsc_sriov_configure(pdev, 0);
	for (vt = 0; vt < PDS_DEV_TYPE_MAX; vt++)
		pdsc_auxbus_dev_del_pf_device(pdsc, vt);

	/* Now we can lock it up and tear it down */
	mutex_lock(&pdsc->config_lock);
	set_bit(PDSC_S_STOPPING_DRIVER, &pdsc->state);

	del_timer_sync(&pdsc->wdtimer);
	if (pdsc->wq) {
		flush_workqueue(pdsc->wq);
		destroy_workqueue(pdsc->wq);
		pdsc->wq = NULL;
	}

	/* Device teardown */
	pdsc_stop(pdsc);
	pdsc_teardown(pdsc, true, PDSC_TEARDOWN_REMOVING);
	pdsc_debugfs_del_dev(pdsc);
	mutex_unlock(&pdsc->config_lock);
	mutex_destroy(&pdsc->config_lock);
	mutex_destroy(&pdsc->devcmd_lock);
	ida_free(&pdsc_pf_ida, pdsc->id);

	/* PCI teardown */
	pci_free_irq_vectors(pdev);
	pci_clear_master(pdev);
	pdsc_unmap_bars(pdsc);
	pci_release_regions(pdev);
	pci_disable_pcie_error_reporting(pdev);
	pci_disable_device(pdev);

	/* Devlink and pdsc struct teardown */
	pdsc_dl_free(pdsc);
}

static struct pci_driver pdsc_driver = {
	.name = PDS_CORE_DRV_NAME,
	.id_table = pdsc_id_table,
	.probe = pdsc_probe,
	.remove = pdsc_remove,
	.sriov_configure = pdsc_sriov_configure,
};

static int __init pdsc_init_module(void)
{
	pdsc_debugfs_create();
	return pci_register_driver(&pdsc_driver);
}

static void __exit pdsc_cleanup_module(void)
{
	pci_unregister_driver(&pdsc_driver);
	pdsc_debugfs_destroy();

	pr_info("removed\n");
}

module_init(pdsc_init_module);
module_exit(pdsc_cleanup_module);
