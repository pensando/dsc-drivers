// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2017 - 2019 Pensando Systems, Inc */

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/etherdevice.h>
#include "ionic.h"
#include "ionic_bus.h"
#include "ionic_dev.h"
#include "ionic_debugfs.h"
#include "ionic_lif.h"

static void ionic_watchdog_cb(struct timer_list *t)
{
	struct ionic *ionic = from_timer(ionic, t, watchdog_timer);
	struct ionic_lif *lif = ionic->master_lif;
	int hb;

	mod_timer(&ionic->watchdog_timer,
		  round_jiffies(jiffies + ionic->watchdog_period));

	hb = ionic_heartbeat_check(ionic);
	dev_dbg(ionic->dev, "%s: hb %d %lu fw %d running %d UP %d\n",
		__func__, hb, ionic->idev.last_hb_time,
		ionic->idev.last_fw_status, netif_running(lif->netdev),
		test_bit(IONIC_LIF_F_UP, lif->state));

	/* check link if we're waiting for link to come back up */
	if (hb >= 0 && lif && netif_running(lif->netdev) &&
	    !test_bit(IONIC_LIF_F_UP, lif->state)) {
		ionic_link_status_check_request(lif);
	}
}

void ionic_init_devinfo(struct ionic *ionic)
{
	struct ionic_dev *idev = &ionic->idev;

	idev->dev_info.asic_type = ioread8(&idev->dev_info_regs->asic_type);
	idev->dev_info.asic_rev = ioread8(&idev->dev_info_regs->asic_rev);

	memcpy_fromio(idev->dev_info.fw_version,
		      idev->dev_info_regs->fw_version,
		      IONIC_DEVINFO_FWVERS_BUFLEN);

	memcpy_fromio(idev->dev_info.serial_num,
		      idev->dev_info_regs->serial_num,
		      IONIC_DEVINFO_SERIAL_BUFLEN);

	idev->dev_info.fw_version[IONIC_DEVINFO_FWVERS_BUFLEN] = 0;
	idev->dev_info.serial_num[IONIC_DEVINFO_SERIAL_BUFLEN] = 0;

	dev_dbg(ionic->dev, "fw_version %s\n", idev->dev_info.fw_version);
}

int ionic_dev_setup(struct ionic *ionic)
{
	struct ionic_dev_bar *bar = ionic->bars;
	unsigned int num_bars = ionic->num_bars;
	struct ionic_dev *idev = &ionic->idev;
	struct device *dev = ionic->dev;
	int size;
	u32 sig;

	/* BAR0: dev_cmd and interrupts */
	if (num_bars < 1) {
		dev_err(dev, "No bars found, aborting\n");
		return -EFAULT;
	}

	if (bar->len < IONIC_BAR0_SIZE) {
		dev_err(dev, "Resource bar size %lu too small, aborting\n",
			bar->len);
		return -EFAULT;
	}

	idev->dev_info_regs = bar->vaddr + IONIC_BAR0_DEV_INFO_REGS_OFFSET;
	idev->dev_cmd_regs = bar->vaddr + IONIC_BAR0_DEV_CMD_REGS_OFFSET;
	idev->intr_status = bar->vaddr + IONIC_BAR0_INTR_STATUS_OFFSET;
	idev->intr_ctrl = bar->vaddr + IONIC_BAR0_INTR_CTRL_OFFSET;

	sig = ioread32(&idev->dev_info_regs->signature);
	if (sig != IONIC_DEV_INFO_SIGNATURE) {
		dev_err(dev, "Incompatible firmware signature %x", sig);
		return -EFAULT;
	}

	ionic_init_devinfo(ionic);

	/* BAR1: doorbells */
	bar++;
	if (num_bars < 2) {
		dev_err(dev, "Doorbell bar missing, aborting\n");
		return -EFAULT;
	}

	idev->last_fw_status = 0xff;
	timer_setup(&ionic->watchdog_timer, ionic_watchdog_cb, 0);
	ionic->watchdog_period = IONIC_WATCHDOG_SECS * HZ;
	mod_timer(&ionic->watchdog_timer,
		  round_jiffies(jiffies + ionic->watchdog_period));

	idev->db_pages = bar->vaddr;
	idev->phy_db_pages = bar->bus_addr;

	/* BAR2: optional controller memory mapping */
	bar++;
	mutex_init(&idev->cmb_inuse_lock);
	if (num_bars < 3) {
		idev->cmb_inuse = NULL;
		idev->phy_cmb_pages = 0;
		idev->cmb_npages = 0;
		return 0;
	}

	idev->phy_cmb_pages = bar->bus_addr;
	idev->cmb_npages = bar->len / PAGE_SIZE;
	size = BITS_TO_LONGS(idev->cmb_npages) * sizeof(long);
	idev->cmb_inuse = kzalloc(size, GFP_KERNEL);
	if (!idev->cmb_inuse) {
		idev->phy_cmb_pages = 0;
		idev->cmb_npages = 0;
	}

	return 0;
}

void ionic_dev_teardown(struct ionic *ionic)
{
	struct ionic_dev *idev = &ionic->idev;

	del_timer_sync(&ionic->watchdog_timer);

	kfree(idev->cmb_inuse);
	idev->cmb_inuse = NULL;
	idev->phy_cmb_pages = 0;
	idev->cmb_npages = 0;

	mutex_destroy(&idev->cmb_inuse_lock);
}

/* Devcmd Interface */
int ionic_heartbeat_check(struct ionic *ionic)
{
	struct ionic_dev *idev = &ionic->idev;
	unsigned long hb_time;
	u8 fw_status;
	u32 hb;

	/* don't check heartbeat on the internal platform device */
	if (ionic->pfdev)
		return 0;

	/* wait a little more than one second before testing again */
	hb_time = jiffies;
	if (time_before(hb_time, (idev->last_hb_time + ionic->watchdog_period)))
		return 0;

	/* firmware is useful only if the running bit is set and
	 * fw_status != 0xff (bad PCI read)
	 */
	fw_status = ioread8(&idev->dev_info_regs->fw_status);
	if (fw_status != 0xff)
		fw_status &= IONIC_FW_STS_F_RUNNING;  /* use only the run bit */

	/* is this a transition? */
	if (fw_status != idev->last_fw_status &&
	    idev->last_fw_status != 0xff) {
		struct ionic_lif *lif = ionic->master_lif;
		bool trigger = false;

		if (!fw_status || fw_status == 0xff) {
			dev_info(ionic->dev, "FW stopped %u\n", fw_status);
			if (lif && !test_bit(IONIC_LIF_F_FW_RESET, lif->state))
				trigger = true;
		} else {
			dev_info(ionic->dev, "FW running %u\n", fw_status);
			if (lif && test_bit(IONIC_LIF_F_FW_RESET, lif->state))
				trigger = true;
		}

		if (trigger) {
			struct ionic_deferred_work *work;

			work = kzalloc(sizeof(*work), GFP_ATOMIC);
			if (!work) {
				dev_err(ionic->dev, "%s OOM\n", __func__);
			} else {
				work->type = IONIC_DW_TYPE_LIF_RESET;
				if (fw_status & IONIC_FW_STS_F_RUNNING &&
				    fw_status != 0xff)
					work->fw_status = 1;
				ionic_lif_deferred_enqueue(&lif->deferred, work);
			}
		}
	}
	idev->last_fw_status = fw_status;

	if (!fw_status || fw_status == 0xff)
		return -ENXIO;

	/* early FW has no heartbeat, else FW will return non-zero */
	hb = ioread32(&idev->dev_info_regs->fw_heartbeat);
	if (!hb)
		return 0;

	/* are we stalled? */
	if (hb == idev->last_hb) {
		/* only complain once for each stall seen */
		if (idev->last_hb_time != 1) {
			dev_info(ionic->dev, "FW heartbeat stalled at %u\n",
				 idev->last_hb);
			idev->last_hb_time = 1;
		}

		return -ENXIO;
	}

	if (idev->last_hb_time == 1)
		dev_info(ionic->dev, "FW heartbeat restored at %d\n", hb);

	idev->last_hb = hb;
	idev->last_hb_time = hb_time;

	return 0;
}

u8 ionic_dev_cmd_status(struct ionic_dev *idev)
{
	return ioread8(&idev->dev_cmd_regs->comp.comp.status);
}

bool ionic_dev_cmd_done(struct ionic_dev *idev)
{
	return ioread32(&idev->dev_cmd_regs->done) & IONIC_DEV_CMD_DONE;
}

void ionic_dev_cmd_comp(struct ionic_dev *idev, union ionic_dev_cmd_comp *comp)
{
	memcpy_fromio(comp, &idev->dev_cmd_regs->comp, sizeof(*comp));
}

void ionic_dev_cmd_go(struct ionic_dev *idev, union ionic_dev_cmd *cmd)
{
	memcpy_toio(&idev->dev_cmd_regs->cmd, cmd, sizeof(*cmd));
	iowrite32(0, &idev->dev_cmd_regs->done);
	iowrite32(1, &idev->dev_cmd_regs->doorbell);
}

/* Device commands */
void ionic_dev_cmd_identify(struct ionic_dev *idev, u8 ver)
{
	union ionic_dev_cmd cmd = {
		.identify.opcode = IONIC_CMD_IDENTIFY,
		.identify.ver = ver,
	};

	ionic_dev_cmd_go(idev, &cmd);
}

void ionic_dev_cmd_init(struct ionic_dev *idev)
{
	union ionic_dev_cmd cmd = {
		.init.opcode = IONIC_CMD_INIT,
		.init.type = 0,
	};

	ionic_dev_cmd_go(idev, &cmd);
}

void ionic_dev_cmd_reset(struct ionic_dev *idev)
{
	union ionic_dev_cmd cmd = {
		.reset.opcode = IONIC_CMD_RESET,
	};

	ionic_dev_cmd_go(idev, &cmd);
}

/* Port commands */
void ionic_dev_cmd_port_identify(struct ionic_dev *idev)
{
	union ionic_dev_cmd cmd = {
		.port_init.opcode = IONIC_CMD_PORT_IDENTIFY,
		.port_init.index = 0,
	};

	ionic_dev_cmd_go(idev, &cmd);
}

void ionic_dev_cmd_port_init(struct ionic_dev *idev)
{
	union ionic_dev_cmd cmd = {
		.port_init.opcode = IONIC_CMD_PORT_INIT,
		.port_init.index = 0,
		.port_init.info_pa = cpu_to_le64(idev->port_info_pa),
	};

	ionic_dev_cmd_go(idev, &cmd);
}

void ionic_dev_cmd_port_reset(struct ionic_dev *idev)
{
	union ionic_dev_cmd cmd = {
		.port_reset.opcode = IONIC_CMD_PORT_RESET,
		.port_reset.index = 0,
	};

	ionic_dev_cmd_go(idev, &cmd);
}

void ionic_dev_cmd_port_state(struct ionic_dev *idev, u8 state)
{
	union ionic_dev_cmd cmd = {
		.port_setattr.opcode = IONIC_CMD_PORT_SETATTR,
		.port_setattr.index = 0,
		.port_setattr.attr = IONIC_PORT_ATTR_STATE,
		.port_setattr.state = state,
	};

	ionic_dev_cmd_go(idev, &cmd);
}

void ionic_dev_cmd_port_speed(struct ionic_dev *idev, u32 speed)
{
	union ionic_dev_cmd cmd = {
		.port_setattr.opcode = IONIC_CMD_PORT_SETATTR,
		.port_setattr.index = 0,
		.port_setattr.attr = IONIC_PORT_ATTR_SPEED,
		.port_setattr.speed = cpu_to_le32(speed),
	};

	ionic_dev_cmd_go(idev, &cmd);
}

void ionic_dev_cmd_port_mtu(struct ionic_dev *idev, u32 mtu)
{
	union ionic_dev_cmd cmd = {
		.port_setattr.opcode = IONIC_CMD_PORT_SETATTR,
		.port_setattr.index = 0,
		.port_setattr.attr = IONIC_PORT_ATTR_MTU,
		.port_setattr.mtu = cpu_to_le32(mtu),
	};

	ionic_dev_cmd_go(idev, &cmd);
}

void ionic_dev_cmd_port_autoneg(struct ionic_dev *idev, u8 an_enable)
{
	union ionic_dev_cmd cmd = {
		.port_setattr.opcode = IONIC_CMD_PORT_SETATTR,
		.port_setattr.index = 0,
		.port_setattr.attr = IONIC_PORT_ATTR_AUTONEG,
		.port_setattr.an_enable = an_enable,
	};

	ionic_dev_cmd_go(idev, &cmd);
}

void ionic_dev_cmd_port_fec(struct ionic_dev *idev, u8 fec_type)
{
	union ionic_dev_cmd cmd = {
		.port_setattr.opcode = IONIC_CMD_PORT_SETATTR,
		.port_setattr.index = 0,
		.port_setattr.attr = IONIC_PORT_ATTR_FEC,
		.port_setattr.fec_type = fec_type,
	};

	ionic_dev_cmd_go(idev, &cmd);
}

void ionic_dev_cmd_port_pause(struct ionic_dev *idev, u8 pause_type)
{
	union ionic_dev_cmd cmd = {
		.port_setattr.opcode = IONIC_CMD_PORT_SETATTR,
		.port_setattr.index = 0,
		.port_setattr.attr = IONIC_PORT_ATTR_PAUSE,
		.port_setattr.pause_type = pause_type,
	};

	ionic_dev_cmd_go(idev, &cmd);
}

void ionic_dev_cmd_port_loopback(struct ionic_dev *idev, u8 loopback_mode)
{
	union ionic_dev_cmd cmd = {
		.port_setattr.opcode = IONIC_CMD_PORT_SETATTR,
		.port_setattr.index = 0,
		.port_setattr.attr = IONIC_PORT_ATTR_LOOPBACK,
		.port_setattr.loopback_mode = loopback_mode,
	};

	ionic_dev_cmd_go(idev, &cmd);
}

/* VF commands */
int ionic_set_vf_config(struct ionic *ionic, int vf, u8 attr, u8 *data)
{
	union ionic_dev_cmd cmd = {
		.vf_setattr.opcode = IONIC_CMD_VF_SETATTR,
		.vf_setattr.attr = attr,
		.vf_setattr.vf_index = vf,
	};
	int err;

	if (vf >= ionic->num_vfs)
		return -EINVAL;

	switch (attr) {
	case IONIC_VF_ATTR_SPOOFCHK:
		cmd.vf_setattr.spoofchk = *data;
		dev_dbg(ionic->dev, "%s: vf %d spoof %d\n",
			__func__, vf, *data);
		break;
	case IONIC_VF_ATTR_TRUST:
		cmd.vf_setattr.trust = *data;
		dev_dbg(ionic->dev, "%s: vf %d trust %d\n",
			__func__, vf, *data);
		break;
	case IONIC_VF_ATTR_LINKSTATE:
		cmd.vf_setattr.linkstate = *data;
		dev_dbg(ionic->dev, "%s: vf %d linkstate %d\n",
			__func__, vf, *data);
		break;
	case IONIC_VF_ATTR_MAC:
		ether_addr_copy(cmd.vf_setattr.macaddr, data);
		dev_dbg(ionic->dev, "%s: vf %d macaddr %pM\n",
			__func__, vf, data);
		break;
	case IONIC_VF_ATTR_VLAN:
		cmd.vf_setattr.vlanid = cpu_to_le16(*(u16 *)data);
		dev_dbg(ionic->dev, "%s: vf %d vlan %d\n",
			__func__, vf, *(u16 *)data);
		break;
	case IONIC_VF_ATTR_RATE:
		cmd.vf_setattr.maxrate = cpu_to_le32(*(u32 *)data);
		dev_dbg(ionic->dev, "%s: vf %d maxrate %d\n",
			__func__, vf, *(u32 *)data);
		break;
	case IONIC_VF_ATTR_STATSADDR:
		cmd.vf_setattr.stats_pa = cpu_to_le64(*(u64 *)data);
		dev_dbg(ionic->dev, "%s: vf %d stats_pa 0x%08llx\n",
			__func__, vf, *(u64 *)data);
		break;
	default:
		return -EINVAL;
	}

	mutex_lock(&ionic->dev_cmd_lock);
	ionic_dev_cmd_go(&ionic->idev, &cmd);
	err = ionic_dev_cmd_wait(ionic, devcmd_timeout);
	mutex_unlock(&ionic->dev_cmd_lock);

	return err;
}

/* LIF commands */
void ionic_dev_cmd_queue_identify(struct ionic_dev *idev,
				  u16 lif_type, u8 qtype, u8 qver)
{
	union ionic_dev_cmd cmd = {
		.q_identify.opcode = IONIC_CMD_Q_IDENTIFY,
		.q_identify.lif_type = lif_type,
		.q_identify.type = qtype,
		.q_identify.ver = qver,
	};

	ionic_dev_cmd_go(idev, &cmd);
}

void ionic_dev_cmd_lif_identify(struct ionic_dev *idev, u8 type, u8 ver)
{
	union ionic_dev_cmd cmd = {
		.lif_identify.opcode = IONIC_CMD_LIF_IDENTIFY,
		.lif_identify.type = type,
		.lif_identify.ver = ver,
	};

	ionic_dev_cmd_go(idev, &cmd);
}

void ionic_dev_cmd_lif_init(struct ionic_dev *idev, u16 lif_index,
			    dma_addr_t info_pa)
{
	union ionic_dev_cmd cmd = {
		.lif_init.opcode = IONIC_CMD_LIF_INIT,
		.lif_init.index = cpu_to_le16(lif_index),
		.lif_init.info_pa = cpu_to_le64(info_pa),
	};

	ionic_dev_cmd_go(idev, &cmd);
}

void ionic_dev_cmd_lif_reset(struct ionic_dev *idev, u16 lif_index)
{
	union ionic_dev_cmd cmd = {
		.lif_init.opcode = IONIC_CMD_LIF_RESET,
		.lif_init.index = cpu_to_le16(lif_index),
	};

	ionic_dev_cmd_go(idev, &cmd);
}

void ionic_dev_cmd_adminq_init(struct ionic_dev *idev, struct ionic_qcq *qcq,
			       u16 lif_index, u16 intr_index)
{
	struct ionic_queue *q = &qcq->q;
	struct ionic_cq *cq = &qcq->cq;

	union ionic_dev_cmd cmd = {
		.q_init.opcode = IONIC_CMD_Q_INIT,
		.q_init.lif_index = cpu_to_le16(lif_index),
		.q_init.type = q->type,
		.q_init.ver = qcq->q.lif->qtype_info[q->type].version,
		.q_init.index = cpu_to_le32(q->index),
		.q_init.flags = cpu_to_le16(IONIC_QINIT_F_IRQ |
					    IONIC_QINIT_F_ENA),
		.q_init.pid = cpu_to_le16(q->pid),
		.q_init.intr_index = cpu_to_le16(intr_index),
		.q_init.ring_size = ilog2(q->num_descs),
		.q_init.ring_base = cpu_to_le64(q->base_pa),
		.q_init.cq_ring_base = cpu_to_le64(cq->base_pa),
	};

	ionic_dev_cmd_go(idev, &cmd);
}

char *ionic_dev_asic_name(u8 asic_type)
{
	switch (asic_type) {
	case IONIC_ASIC_TYPE_CAPRI:
		return "Capri";
	default:
		return "Unknown";
	}
}

int ionic_db_page_num(struct ionic_lif *lif, int pid)
{
	return (lif->hw_index * lif->dbid_count) + pid;
}

static void ionic_txrx_notify(struct ionic *ionic,
			      int lif_index, int qcq_id, bool is_tx)
{
	struct ionic_lif *lif;

	lif = radix_tree_lookup(&ionic->lifs, lif_index);
	if (!lif)
		return;

	if (is_tx)
		lif->txqcqs[qcq_id].qcq->armed = false;
	else
		lif->rxqcqs[qcq_id].qcq->armed = false;

	/* We schedule rx napi, it handles both tx and rx */
	napi_schedule_irqoff(&lif->rxqcqs[qcq_id].qcq->napi);
}

static bool ionic_next_eq_comp(struct ionic_eq *eq, int ring_index,
			       struct ionic_eq_comp *comp)
{
	struct ionic_eq_ring *ring = &eq->ring[ring_index];
	struct ionic_eq_comp *qcomp;
	u8 gen_color;

	qcomp = &ring->base[ring->index];
	gen_color = qcomp->gen_color;

	if (gen_color == (u8)(ring->gen_color - 1))
		return false;

	/* Make sure ring descriptor is up-to-date before reading */
	smp_rmb();
	*comp = *qcomp;
	gen_color = comp->gen_color;

	if (gen_color != ring->gen_color) {
		dev_err(eq->ionic->dev,
			"eq %u ring %u missed %u events\n",
			eq->index, ring_index,
			eq->depth * (gen_color - ring->gen_color));

		ring->gen_color = gen_color;
	}

	ring->index = (ring->index + 1) & (eq->depth - 1);
	ring->gen_color += ring->index == 0;

	return true;
}

static int ionic_poll_eq_ring(struct ionic_eq *eq, int ring_index)
{
	struct ionic_eq_comp comp;
	int budget = eq->depth;
	int credits = 0;
	int code;

	while (credits < budget && ionic_next_eq_comp(eq, ring_index, &comp)) {
		code = le16_to_cpu(comp.code);

		switch (code) {
		case IONIC_EQ_COMP_CODE_NONE:
			break;
		case IONIC_EQ_COMP_CODE_RX_COMP:
		case IONIC_EQ_COMP_CODE_TX_COMP:
			ionic_txrx_notify(eq->ionic,
					  le16_to_cpu(comp.lif_index),
					  le32_to_cpu(comp.qid),
					  code == IONIC_EQ_COMP_CODE_TX_COMP);
			break;
		default:
			dev_warn(eq->ionic->dev,
				 "eq %u ring %u unrecognized event %u\n",
				 eq->index, ring_index, code);
			break;
		}

		credits++;
	}

	return credits;
}

static irqreturn_t ionic_eq_isr(int irq, void *data)
{
	struct ionic_eq *eq = data;
	int credits;

	credits = ionic_poll_eq_ring(eq, 0) + ionic_poll_eq_ring(eq, 1);
	ionic_intr_credits(eq->ionic->idev.intr_ctrl, eq->intr.index,
			   credits, IONIC_INTR_CRED_UNMASK);

	return IRQ_HANDLED;
}

static int ionic_request_eq_irq(struct ionic *ionic, struct ionic_eq *eq)
{
	struct device *dev = ionic->dev;
	struct ionic_intr_info *intr = &eq->intr;
	const char *name = dev_name(dev);

	snprintf(intr->name, sizeof(intr->name),
		 "%s-%s-eq%d", IONIC_DRV_NAME, name, eq->index);

	return devm_request_irq(dev, intr->vector, ionic_eq_isr,
				0, intr->name, eq);
}

static int ionic_eq_alloc(struct ionic *ionic, int index)
{
	const int ring_bytes = sizeof(struct ionic_eq_comp) * IONIC_EQ_DEPTH;
	struct ionic_eq *eq;
	int err;

	eq = kzalloc(sizeof(*eq), GFP_KERNEL);
	eq->ionic = ionic;
	eq->index = index;
	eq->depth = IONIC_EQ_DEPTH;

	err = ionic_intr_alloc(ionic, &eq->intr);
	if (err) {
		dev_warn(ionic->dev, "no intr for eq %u: %d\n", index, err);
		goto err_out;
	}

	err = ionic_bus_get_irq(ionic, eq->intr.index);
	if (err < 0) {
		dev_warn(ionic->dev, "no vector for eq %u: %d\n", index, err);
		goto err_out_free_intr;
	}
	eq->intr.vector = err;

	ionic_intr_mask_assert(ionic->idev.intr_ctrl, eq->intr.index,
			       IONIC_INTR_MASK_SET);

	/* try to get the irq on the local numa node first */
	eq->intr.cpu = cpumask_local_spread(eq->intr.index,
					    dev_to_node(ionic->dev));
	if (eq->intr.cpu != -1)
		cpumask_set_cpu(eq->intr.cpu, &eq->intr.affinity_mask);

	eq->ring[0].gen_color = 1;
	eq->ring[0].base = dma_alloc_coherent(ionic->dev, ring_bytes,
					      &eq->ring[0].base_pa,
					      GFP_KERNEL);

	eq->ring[1].gen_color = 1;
	eq->ring[1].base = dma_alloc_coherent(ionic->dev, ring_bytes,
					      &eq->ring[1].base_pa,
					      GFP_KERNEL);

	ionic->eqs[index] = eq;

	ionic_debugfs_add_eq(eq);

	return 0;

err_out_free_intr:
	ionic_intr_free(ionic, eq->intr.index);
err_out:
	kfree(eq);
	return err;
}

int ionic_eqs_alloc(struct ionic *ionic)
{
	size_t eq_size;
	int i, err;

	eq_size = sizeof(*ionic->eqs) * ionic->neth_eqs;
	ionic->eqs = kzalloc(eq_size, GFP_KERNEL);
	if (!ionic->eqs)
		return -ENOMEM;

	for (i = 0; i < ionic->neth_eqs; i++) {
		err = ionic_eq_alloc(ionic, i);
		if (err)
			return err;
	}

	return 0;
}

static void ionic_eq_free(struct ionic_eq *eq)
{
	const int ring_bytes = sizeof(struct ionic_eq_comp) * IONIC_EQ_DEPTH;
	struct ionic *ionic = eq->ionic;

	eq->ionic->eqs[eq->index] = NULL;

	dma_free_coherent(ionic->dev, ring_bytes,
			  eq->ring[0].base,
			  eq->ring[0].base_pa);
	dma_free_coherent(ionic->dev, ring_bytes,
			  eq->ring[1].base,
			  eq->ring[1].base_pa);
	ionic_intr_free(ionic, eq->intr.index);
	kfree(eq);
}

void ionic_eqs_free(struct ionic *ionic)
{
	int i;

	if (!ionic->eqs)
		return;

	for (i = 0; i < ionic->neth_eqs; i++) {
		if (ionic->eqs[i])
			ionic_eq_free(ionic->eqs[i]);
	}

	kfree(ionic->eqs);
	ionic->eqs = NULL;
	ionic->neth_eqs = 0;
}

static void ionic_eq_deinit(struct ionic_eq *eq)
{
	struct ionic *ionic = eq->ionic;
	union ionic_dev_cmd cmd = {
		.q_control = {
			.opcode = IONIC_CMD_Q_CONTROL,
			.type = IONIC_QTYPE_EQ,
			.index = cpu_to_le32(eq->index),
			.oper = IONIC_Q_DISABLE,
		},
	};

	if (!eq->is_init)
		return;
	eq->is_init = false;

	mutex_lock(&ionic->dev_cmd_lock);
	ionic_dev_cmd_go(&ionic->idev, &cmd);
	ionic_dev_cmd_wait(ionic, devcmd_timeout);
	mutex_unlock(&ionic->dev_cmd_lock);

	ionic_intr_mask(ionic->idev.intr_ctrl, eq->intr.index,
			IONIC_INTR_MASK_SET);
	synchronize_irq(eq->intr.vector);

	irq_set_affinity_hint(eq->intr.vector, NULL);
	devm_free_irq(ionic->dev, eq->intr.vector, eq);
}

void ionic_eqs_deinit(struct ionic *ionic)
{
	int i;

	if (!ionic->eqs)
		return;

	for (i = 0; i < ionic->neth_eqs; i++) {
		if (ionic->eqs[i])
			ionic_eq_deinit(ionic->eqs[i]);
	}
}

static int ionic_eq_init(struct ionic_eq *eq)
{
	struct ionic *ionic = eq->ionic;
	union ionic_q_identity *q_ident;
	union ionic_dev_cmd cmd = {
		.q_init = {
			.opcode = IONIC_CMD_Q_INIT,
			.type = IONIC_QTYPE_EQ,
			.ver = 0,
			.index = cpu_to_le32(eq->index),
			.intr_index = cpu_to_le16(eq->intr.index),
			.flags = cpu_to_le16(IONIC_QINIT_F_IRQ |
					     IONIC_QINIT_F_ENA),
			.ring_size = ilog2(eq->depth),
			.ring_base = cpu_to_le64(eq->ring[0].base_pa),
			.cq_ring_base = cpu_to_le64(eq->ring[1].base_pa),
		},
	};
	int err;

	q_ident = (union ionic_q_identity *)&ionic->idev.dev_cmd_regs->data;

	mutex_lock(&ionic->dev_cmd_lock);
	ionic_dev_cmd_queue_identify(&ionic->idev, IONIC_LIF_TYPE_CLASSIC,
				     IONIC_QTYPE_EQ, 0);
	err = ionic_dev_cmd_wait(ionic, devcmd_timeout);
	cmd.q_init.ver = q_ident->version;
	mutex_unlock(&ionic->dev_cmd_lock);

	if (err == -EINVAL) {
		dev_err(ionic->dev, "eq init failed, not supported\n");
		return err;
	} else if (err == -EIO) {
		dev_err(ionic->dev, "q_ident eq failed, not supported on older FW\n");
		return err;
	} else if (err) {
		dev_warn(ionic->dev, "eq version type request failed %d, defaulting to %d\n",
			 err, cmd.q_init.ver);
	}

	ionic_intr_mask(ionic->idev.intr_ctrl, eq->intr.index,
			IONIC_INTR_MASK_SET);
	ionic_intr_clean(ionic->idev.intr_ctrl, eq->intr.index);

	err = ionic_request_eq_irq(ionic, eq);
	if (err) {
		dev_warn(ionic->dev, "eq %d irq request failed %d\n",
			 eq->index, err);
		return err;
	}

	mutex_lock(&ionic->dev_cmd_lock);
	ionic_dev_cmd_go(&ionic->idev, &cmd);
	err = ionic_dev_cmd_wait(ionic, devcmd_timeout);
	mutex_unlock(&ionic->dev_cmd_lock);

	if (err) {
		dev_err(ionic->dev, "eq %d init failed %d\n",
			eq->index, err);
		return err;
	}

	ionic_intr_mask(ionic->idev.intr_ctrl, eq->intr.index,
			IONIC_INTR_MASK_CLEAR);

	eq->is_init = true;

	return 0;
}

int ionic_eqs_init(struct ionic *ionic)
{
	int i, err;

	for (i = 0; i < ionic->neth_eqs; i++) {
		if (ionic->eqs[i]) {
			err = ionic_eq_init(ionic->eqs[i]);
			if (err)
				return err;
		}
	}

	return 0;
}

int ionic_cq_init(struct ionic_lif *lif, struct ionic_cq *cq,
		  struct ionic_intr_info *intr,
		  unsigned int num_descs, size_t desc_size)
{
	struct ionic_cq_info *cur;
	unsigned int ring_size;
	unsigned int i;

	if (desc_size == 0 || !is_power_of_2(num_descs))
		return -EINVAL;

	ring_size = ilog2(num_descs);
	if (ring_size < 2 || ring_size > 16)
		return -EINVAL;

	cq->lif = lif;
	cq->bound_intr = intr;
	cq->num_descs = num_descs;
	cq->desc_size = desc_size;
	cq->tail_idx = 0;
	cq->done_color = 1;

	cur = cq->info;

	for (i = 0; i < num_descs; i++) {
		if (i + 1 == num_descs) {
			cur->next = cq->info;
			cur->last = true;
		} else {
			cur->next = cur + 1;
		}
		cur->index = i;
		cur++;
	}

	return 0;
}

void ionic_cq_map(struct ionic_cq *cq, void *base, dma_addr_t base_pa)
{
	struct ionic_cq_info *cur;
	unsigned int i;

	cq->base = base;
	cq->base_pa = base_pa;

	for (i = 0, cur = cq->info; i < cq->num_descs; i++, cur++)
		cur->cq_desc = base + (i * cq->desc_size);
}

void ionic_cq_bind(struct ionic_cq *cq, struct ionic_queue *q)
{
	cq->bound_q = q;
}

unsigned int ionic_cq_service(struct ionic_cq *cq, unsigned int work_to_do,
			      ionic_cq_cb cb, ionic_cq_done_cb done_cb,
			      void *done_arg)
{
	unsigned int work_done = 0;
	struct ionic_cq_info *cq_info;

	if (work_to_do == 0)
		return 0;

	cq_info = &cq->info[cq->tail_idx];
	while (cb(cq, cq_info)) {
		if (cq->tail_idx == cq->num_descs - 1)
			cq->done_color = !cq->done_color;
		cq->tail_idx = (cq->tail_idx + 1) & (cq->num_descs - 1);
		cq_info = &cq->info[cq->tail_idx];
		DEBUG_STATS_CQE_CNT(cq);

		if (++work_done >= work_to_do)
			break;
	}

	if (work_done && done_cb)
		done_cb(done_arg);

	return work_done;
}

int ionic_q_init(struct ionic_lif *lif, struct ionic_dev *idev,
		 struct ionic_queue *q, unsigned int index, const char *name,
		 unsigned int num_descs, size_t desc_size,
		 size_t sg_desc_size, unsigned int pid)
{
	struct ionic_desc_info *cur;
	unsigned int ring_size;
	unsigned int i;

	if (desc_size == 0 || !is_power_of_2(num_descs))
		return -EINVAL;

	ring_size = ilog2(num_descs);
	if (ring_size < 2 || ring_size > 16)
		return -EINVAL;

	q->lif = lif;
	q->idev = idev;
	q->index = index;
	q->num_descs = num_descs;
	q->desc_size = desc_size;
	q->sg_desc_size = sg_desc_size;
	q->tail_idx = 0;
	q->head_idx = 0;
	q->pid = pid;

	snprintf(q->name, sizeof(q->name), "L%d-%s%u", lif->index, name, index);

	cur = q->info;

	for (i = 0; i < num_descs; i++) {
		if (i + 1 == num_descs)
			cur->next = q->info;
		else
			cur->next = cur + 1;
		cur->index = i;
		cur->left = num_descs - i;
		cur++;
	}

	return 0;
}

void ionic_q_map(struct ionic_queue *q, void *base, dma_addr_t base_pa)
{
	struct ionic_desc_info *cur;
	unsigned int i;

	q->base = base;
	q->base_pa = base_pa;

	for (i = 0, cur = q->info; i < q->num_descs; i++, cur++)
		cur->desc = base + (i * q->desc_size);
}

void ionic_q_sg_map(struct ionic_queue *q, void *base, dma_addr_t base_pa)
{
	struct ionic_desc_info *cur;
	unsigned int i;

	q->sg_base = base;
	q->sg_base_pa = base_pa;

	for (i = 0, cur = q->info; i < q->num_descs; i++, cur++)
		cur->sg_desc = base + (i * q->sg_desc_size);
}

void ionic_q_post(struct ionic_queue *q, bool ring_doorbell, ionic_desc_cb cb,
		  void *cb_arg)
{
	struct device *dev = q->dev;
	struct ionic_lif *lif = q->lif;
	struct ionic_desc_info *desc_info;

	desc_info = &q->info[q->head_idx];
	desc_info->cb = cb;
	desc_info->cb_arg = cb_arg;

	q->head_idx = (q->head_idx + 1) & (q->num_descs - 1);

	q->depth = q->num_descs - ionic_q_space_avail(q);
	q->depth_max = max_t(u64, q->depth, q->depth_max);

	dev_dbg(dev, "%s: lif=%d qname=%s hw_type=%d hw_index=%d p_index=%d ringdb=%d\n",
		__func__, q->lif->index, q->name, q->hw_type, q->hw_index,
		q->head_idx, ring_doorbell);

	if (ring_doorbell)
		ionic_dbell_ring(lif->kern_dbpage, q->hw_type,
				 q->dbval | q->head_idx);
}

static bool ionic_q_is_posted(struct ionic_queue *q, unsigned int pos)
{
	unsigned int mask, tail, head;

	mask = q->num_descs - 1;
	tail = q->tail_idx;
	head = q->head_idx;

	return ((pos - tail) & mask) < ((head - tail) & mask);
}

void ionic_q_service(struct ionic_queue *q, struct ionic_cq_info *cq_info,
		     unsigned int stop_index)
{
	struct ionic_desc_info *desc_info;
	ionic_desc_cb cb;
	void *cb_arg;

	/* check for empty queue */
	if (q->tail_idx == q->head_idx)
		return;

	/* stop index must be for a descriptor that is not yet completed */
	if (unlikely(!ionic_q_is_posted(q, stop_index)))
		dev_err(q->dev,
			"ionic stop is not posted %s stop %u tail %u head %u\n",
			q->name, stop_index, q->tail_idx, q->head_idx);

	do {
		desc_info = &q->info[q->tail_idx];
		q->tail_idx = (q->tail_idx + 1) & (q->num_descs - 1);

		cb = desc_info->cb;
		cb_arg = desc_info->cb_arg;

		desc_info->cb = NULL;
		desc_info->cb_arg = NULL;

		if (cb)
			cb(q, desc_info, cq_info, cb_arg);
	} while (desc_info->index != stop_index);
}
