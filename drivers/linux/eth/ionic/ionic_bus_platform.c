// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2017 - 2019 Pensando Systems, Inc */

#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/io.h>
#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/msi.h>
#include <linux/interrupt.h>

#include "ionic.h"
#include "ionic_bus.h"
#include "ionic_lif.h"
#include "ionic_debugfs.h"

#define IONIC_DEV_BAR         0
#define IONIC_INTR_CTRL_BAR   1
#define IONIC_MSIX_CFG_BAR    2
#define IONIC_DOORBELL_BAR    3
#define IONIC_NUM_OF_BAR      4

#define IONIC_INTR_MSIXCFG_STRIDE     0x10

struct ionic_intr_msixcfg {
	__le64 msgaddr;
	__le32 msgdata;
	__le32 vector_ctrl;
};

static void *ionic_intr_msixcfg_addr(struct device *mnic_dev, const int intr)
{
	struct ionic_dev *idev = (struct ionic_dev *) mnic_dev->platform_data;

	dev_info(mnic_dev, "msix_cfg_base: %p\n", idev->msix_cfg_base);
	return (idev->msix_cfg_base + (intr * IONIC_INTR_MSIXCFG_STRIDE));
}

static void ionic_intr_msixcfg(struct device *mnic_dev,
			       const int intr, const u64 msgaddr,
			       const u32 msgdata, const int vctrl)
{
	volatile void *pa = ionic_intr_msixcfg_addr(mnic_dev, intr);

	writeq(msgaddr, (pa + offsetof(struct ionic_intr_msixcfg, msgaddr)));
	writel(msgdata, (pa + offsetof(struct ionic_intr_msixcfg, msgdata)));
	writel(vctrl, (pa + offsetof(struct ionic_intr_msixcfg, vector_ctrl)));
}

int ionic_bus_get_irq(struct ionic *ionic, unsigned int num)
{
	struct msi_desc *desc;
	int i = 0;

	for_each_msi_entry(desc, ionic->dev) {
		if (i == num) {
			pr_info("[i = %d] msi_entry: %d.%d\n",
				i, desc->platform.msi_index,
				desc->irq);

			return desc->irq;
		}
		i++;
	}

	return -1; //return error if user is asking more irqs than allocated
}

const char *ionic_bus_info(struct ionic *ionic)
{
	return ionic->pfdev->name;
}

static void ionic_mnic_set_msi_msg(struct msi_desc *desc, struct msi_msg *msg)
{
	dev_dbg(desc->dev, "msi_index: [%d] (msi_addr hi_lo): %x_%x msi_data: %x\n",
		desc->platform.msi_index, msg->address_hi,
		msg->address_lo, msg->data);

	ionic_intr_msixcfg(desc->dev, desc->platform.msi_index,
		     (((u64)msg->address_hi << 32) | msg->address_lo),
		     msg->data, 0/*vctrl*/);
}

int ionic_bus_alloc_irq_vectors(struct ionic *ionic, unsigned int nintrs)
{
	int err = 0;

	err = platform_msi_domain_alloc_irqs(ionic->dev, nintrs,
					     ionic_mnic_set_msi_msg);
	if (err)
		return err;

	return nintrs;
}

void ionic_bus_free_irq_vectors(struct ionic *ionic)
{
	platform_msi_domain_free_irqs(ionic->dev);
}

struct net_device *ionic_alloc_netdev(struct ionic *ionic)
{
	struct net_device *netdev = NULL;
	struct ionic_lif *lif;
	int nqueues;

	nqueues = ionic->ntxqs_per_lif + (ionic->nlifs - 1);
	netdev = alloc_netdev_mqs(sizeof(struct ionic_lif), ionic->pfdev->name,
				  NET_NAME_USER, ether_setup, nqueues, nqueues);
	if (!netdev)
		return netdev;

	lif = netdev_priv(netdev);

	/* lif name is used for naming the interrupt handler so better
	 * to name them differently for mnic
	 */
	snprintf(lif->name, sizeof(lif->name), "%s-", ionic->pfdev->name);

	return netdev;
}

static int ionic_mnic_dev_setup(struct ionic *ionic)
{
	unsigned int num_bars = ionic->num_bars;
	struct ionic_dev *idev = &ionic->idev;
	u32 sig;

	if (num_bars < IONIC_NUM_OF_BAR)
		return -EFAULT;

	idev->dev_info_regs = ionic->bars[IONIC_DEV_BAR].vaddr;
	idev->dev_cmd_regs = ionic->bars[IONIC_DEV_BAR].vaddr +
					offsetof(union ionic_dev_regs, devcmd);
	idev->intr_ctrl = ionic->bars[IONIC_INTR_CTRL_BAR].vaddr;
	idev->msix_cfg_base = ionic->bars[IONIC_MSIX_CFG_BAR].vaddr;

	/* save the idev into dev->platform_data so we can use it later */
	ionic->dev->platform_data = idev;

	sig = ioread32(&idev->dev_info_regs->signature);
	if (sig != IONIC_DEV_INFO_SIGNATURE)
		return -EFAULT;

	ionic_init_devinfo(ionic);

	idev->db_pages = ionic->bars[IONIC_DOORBELL_BAR].vaddr;
	idev->phy_db_pages = ionic->bars[IONIC_DOORBELL_BAR].bus_addr;

	ionic_debugfs_add_dev_cmd(ionic);

	return 0;
}

static int ionic_map_bars(struct ionic *ionic)
{
	struct platform_device *pfdev = ionic->pfdev;
	struct ionic_dev_bar *bars = ionic->bars;
	struct device *dev = ionic->dev;
	struct resource *res;
	unsigned int i, j;
	void *base;

	ionic->num_bars = 0;
	for (i = 0, j = 0; i < IONIC_BARS_MAX; i++) {
		res = platform_get_resource(pfdev, IORESOURCE_MEM, i);
		if (!res)
			continue;
		base = devm_ioremap_resource(dev, res);
		if (IS_ERR(base)) {
			dev_err(dev, "Cannot memory-map BAR %d, aborting\n", j);
			return -ENODEV;
		}
		bars[j].len = res->end - res->start + 1;
		bars[j].vaddr = base;
		bars[j].bus_addr = res->start;
		ionic->num_bars++;
		j++;
	}

	ionic_debugfs_add_bars(ionic);

	return 0;
}

static void ionic_unmap_bars(struct ionic *ionic)
{
	struct ionic_dev_bar *bars = ionic->bars;
	struct device *dev = ionic->dev;
	unsigned int i;

	for (i = 0; i < IONIC_BARS_MAX; i++)
		if (bars[i].vaddr) {
			dev_info(dev, "Unmapping BAR %d @%p, bus_addr: %llx\n",
				 i, bars[i].vaddr, bars[i].bus_addr);
			devm_iounmap(dev, bars[i].vaddr);
			devm_release_mem_region(dev, bars[i].bus_addr, bars[i].len);
		}
}

void __iomem *ionic_bus_map_dbpage(struct ionic *ionic, int page_num)
{
	return ionic->idev.db_pages;
}

void ionic_bus_unmap_dbpage(struct ionic *ionic, void __iomem *page)
{
}

phys_addr_t ionic_bus_phys_dbpage(struct ionic *ionic, int page_num)
{
	return 0;
}

static int ionic_probe(struct platform_device *pfdev)
{
	struct device *dev = &pfdev->dev;
	struct ionic *ionic;
	int err;

	ionic = devm_kzalloc(dev, sizeof(*ionic), GFP_KERNEL);
	if (!ionic)
		return -ENOMEM;

	ionic->pfdev = pfdev;
	platform_set_drvdata(pfdev, ionic);
	ionic->dev = dev;
	mutex_init(&ionic->dev_cmd_lock);

	err = ionic_set_dma_mask(ionic);
	if (err) {
		dev_err(dev, "Cannot set DMA mask, aborting\n");
		return err;
	}

	ionic_debugfs_add_dev(ionic);

	/* Setup platform device */
	err = ionic_map_bars(ionic);
	if (err)
		goto err_out_unmap_bars;

	/* Discover ionic dev resources */
	err = ionic_mnic_dev_setup(ionic);
	if (err) {
		dev_err(dev, "Cannot setup device, aborting\n");
		goto err_out_unmap_bars;
	}

	err = ionic_identify(ionic);
	if (err) {
		dev_err(dev, "Cannot identify device, aborting\n");
		goto err_out_unmap_bars;
	}

	err = ionic_init(ionic);
	if (err) {
		dev_err(dev, "Cannot init device, aborting\n");
		goto err_out_unmap_bars;
	}

	/* Configure the ports */
	err = ionic_port_identify(ionic);
	if (err) {
		dev_err(dev, "Cannot identify port: %d, aborting\n", err);
		goto err_out_unmap_bars;
	}

	if (ionic->ident.port.type == IONIC_ETH_HOST_MGMT ||
	    ionic->ident.port.type == IONIC_ETH_MNIC_INTERNAL_MGMT)
		ionic->is_mgmt_nic = true;

	err = ionic_port_init(ionic);
	if (err) {
		dev_err(dev, "Cannot init port: %d, aborting\n", err);
		goto err_out_unmap_bars;
	}

	/* Allocate and init LIFs, creating a netdev per LIF */
	err = ionic_lif_identify(ionic, IONIC_LIF_TYPE_CLASSIC,
				 &ionic->ident.lif);
	if (err) {
		dev_err(dev, "Cannot identify LIFs: %d, aborting\n", err);
		goto err_out_unmap_bars;
	}

	err = ionic_lifs_size(ionic);
	if (err) {
		dev_err(dev, "Cannot size LIFs, aborting\n");
		goto err_out_unmap_bars;
	}

	err = ionic_lifs_alloc(ionic);
	if (err) {
		dev_err(dev, "Cannot allocate LIFs, aborting\n");
		goto err_out_free_lifs;
	}

	err = ionic_lifs_init(ionic);
	if (err) {
		dev_err(dev, "Cannot init LIFs, aborting\n");
		goto err_out_deinit_lifs;
	}

	err = ionic_lifs_register(ionic);
	if (err) {
		dev_err(dev, "Cannot register LIFs, aborting\n");
		goto err_out_unregister_lifs;
	}

	return 0;

err_out_unregister_lifs:
	ionic_lifs_unregister(ionic);
err_out_deinit_lifs:
	ionic_lifs_deinit(ionic);
err_out_free_lifs:
	ionic_lifs_free(ionic);
	ionic_bus_free_irq_vectors(ionic);
err_out_unmap_bars:
	ionic_unmap_bars(ionic);
	ionic_debugfs_del_dev(ionic);
	mutex_destroy(&ionic->dev_cmd_lock);
	platform_set_drvdata(pfdev, NULL);

	return err;
}
EXPORT_SYMBOL_GPL(ionic_probe);

static int ionic_remove(struct platform_device *pfdev)
{
	struct ionic *ionic = platform_get_drvdata(pfdev);

	if (ionic) {
		ionic_lifs_unregister(ionic);
		ionic_lifs_deinit(ionic);
		ionic_lifs_free(ionic);
		ionic_port_reset(ionic);
		ionic_reset(ionic);
		ionic_bus_free_irq_vectors(ionic);
		ionic_unmap_bars(ionic);
		ionic_debugfs_del_dev(ionic);

		mutex_destroy(&ionic->dev_cmd_lock);

		dev_info(ionic->dev, "removed\n");
	}

	return 0;
}
EXPORT_SYMBOL_GPL(ionic_remove);

static const struct of_device_id mnic_of_match[] = {
		{.compatible = "pensando,ionic-mnic"},
			{/* end of table */}
};

static struct platform_driver ionic_driver = {
	.probe = ionic_probe,
	.remove = ionic_remove,
	.driver = {
		.name = "ionic-mnic",
		.owner = THIS_MODULE,
		.of_match_table = mnic_of_match,
	},
};

int ionic_bus_register_driver(void)
{
	return platform_driver_register(&ionic_driver);
}

void ionic_bus_unregister_driver(void)
{
	platform_driver_unregister(&ionic_driver);
}
