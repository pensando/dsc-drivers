/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2017 - 2019 Pensando Systems, Inc */

#ifndef _IONIC_H_
#define _IONIC_H_

struct ionic_lif;

#include <linux/radix-tree.h>

#include "kcompat.h"

#include "ionic_if.h"
#include "ionic_dev.h"
#include "ionic_devlink.h"

#define IONIC_DRV_NAME		"ionic"
#define IONIC_DRV_DESCRIPTION	"Pensando Ethernet NIC Driver"
#define IONIC_DRV_VERSION	"1.8.0"

#define PCI_VENDOR_ID_PENSANDO			0x1dd8

#define PCI_DEVICE_ID_PENSANDO_IONIC_ETH_PF	0x1002
#define PCI_DEVICE_ID_PENSANDO_IONIC_ETH_VF	0x1003
#define PCI_DEVICE_ID_PENSANDO_IONIC_ETH_MGMT	0x1004

#define DEVCMD_TIMEOUT  5
#define SHORT_TIMEOUT   1
#define MAX_ETH_EQS	64

extern unsigned int max_slaves;
extern unsigned int rx_copybreak;
extern unsigned int tx_budget;
extern unsigned int devcmd_timeout;

struct ionic_vf {
	u16	 index;
	u8	 macaddr[6];
	__le32	 maxrate;
	__le16	 vlanid;
	u8	 spoofchk;
	u8	 trusted;
	u8	 linkstate;
	dma_addr_t       stats_pa;
	struct ionic_lif_stats stats;
};

struct ionic {
	struct pci_dev *pdev;
	struct platform_device *pfdev;
	struct device *dev;
	struct ionic_dev idev;
	struct mutex dev_cmd_lock;	/* lock for dev_cmd operations */
	struct dentry *dentry;
	struct ionic_dev_bar bars[IONIC_BARS_MAX];
	unsigned int num_bars;
	bool is_mgmt_nic;
	struct ionic_lif *master_lif;
	struct radix_tree_root lifs;
	struct ionic_eq **eqs;
	struct ionic_identity ident;
	unsigned int nnqs_per_lif;
	unsigned int nrdma_eqs_per_lif;
	unsigned int ntxqs_per_lif;
	unsigned int nrxqs_per_lif;
	unsigned int nlifs;
	unsigned int neth_eqs;
	DECLARE_BITMAP(lifbits, IONIC_LIFS_MAX);
	DECLARE_BITMAP(ethbits, IONIC_LIFS_MAX);
	unsigned int nintrs;
	DECLARE_BITMAP(intrs, IONIC_INTR_CTRL_REGS_MAX);
#ifndef HAVE_PCI_IRQ_API
	struct msix_entry *msix;
#endif
	struct work_struct nb_work;
	struct notifier_block nb;
#ifdef IONIC_DEVLINK
	struct devlink_port dl_port;
#endif
	struct rw_semaphore vf_op_lock;	/* lock for VF operations */
	struct ionic_vf *vfs;
	int num_vfs;

	struct timer_list watchdog_timer;
	int watchdog_period;
};

/* Since we have a bitmap of the allocated eth lifs, we can use
 * that to look up each lif specifically, rather than digging
 * through the whole tree with radix_tree_for_each_slot
 */
#define for_each_eth_lif(_ion, _bit, _lif) \
	for ((_bit) = find_first_bit((_ion)->ethbits, IONIC_LIFS_MAX),   \
		(_lif) = radix_tree_lookup(&(_ion)->lifs, (_bit));       \
	     (_bit) < IONIC_LIFS_MAX;                                    \
	     (_bit) = find_next_bit((_ion)->ethbits,                     \
				    IONIC_LIFS_MAX, ((_bit) + 1)),       \
		(_lif) = radix_tree_lookup(&(_ion)->lifs, (_bit)))

int ionic_napi(struct napi_struct *napi, int budget, ionic_cq_cb cb,
	       ionic_cq_done_cb done_cb, void *done_arg);

int ionic_adminq_post(struct ionic_lif *lif, struct ionic_admin_ctx *ctx);
int ionic_adminq_post_wait(struct ionic_lif *lif, struct ionic_admin_ctx *ctx);
int ionic_dev_cmd_wait(struct ionic *ionic, unsigned long max_wait);
int ionic_set_dma_mask(struct ionic *ionic);
int ionic_setup(struct ionic *ionic);

int ionic_identify(struct ionic *ionic);
int ionic_init(struct ionic *ionic);
int ionic_reset(struct ionic *ionic);

int ionic_port_identify(struct ionic *ionic);
int ionic_port_init(struct ionic *ionic);
int ionic_port_reset(struct ionic *ionic);

#endif /* _IONIC_H_ */
