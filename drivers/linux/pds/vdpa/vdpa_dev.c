// SPDX-License-Identifier: GPL-2.0-only
/* Copyright(c) 2022 Pensando Systems, Inc */

#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/sysfs.h>
#include <linux/types.h>
#include <linux/vdpa.h>
#include <uapi/linux/virtio_pci.h>
#include <uapi/linux/vdpa.h>

#include "pds_core_if.h"
#include "pds_vdpa.h"
#include "pds_intr.h"

#include "vdpa_dev.h"
#include "pci_drv.h"
#include "aux_drv.h"
#include "pci_drv.h"
#include "cmds.h"
#include "debugfs.h"

static int
pds_vdpa_setup_driver(struct pds_vdpa_device *pdsv)
{
	struct device *dev = &pdsv->vdpa_dev.dev;
	int err = 0;
	int i;

	// TODO
	// we've made it to DRIVER_OK, so now we need to
	// set up whatever else needs to be done to have
	// operating queues for the features that were
	// negotiated and how ever many queues requested

	/* Verify all vqs[] are in ready state */
	for (i = 0; i < pdsv->hw.num_vqs; i++) {
		if (!pdsv->hw.vqs[i].ready) {
			dev_warn(dev, "%s: qid %d not ready\n", __func__, i);
			err = -ENOENT;
		}
	}

	return err;
}

static struct pds_vdpa_device *
vdpa_to_pdsv(struct vdpa_device *vdpa_dev)
{
	return container_of(vdpa_dev, struct pds_vdpa_device, vdpa_dev);
}

static struct pds_vdpa_hw *
vdpa_to_hw(struct vdpa_device *vdpa_dev)
{
	struct pds_vdpa_device *pdsv = vdpa_to_pdsv(vdpa_dev);

	return &pdsv->hw;
}

static int
pds_vdpa_set_vq_address(struct vdpa_device *vdpa_dev, u16 qid,
			u64 desc_addr, u64 driver_addr, u64 device_addr)
{
	struct pds_vdpa_device *pdsv = vdpa_to_pdsv(vdpa_dev);
	struct pds_vdpa_hw *hw = vdpa_to_hw(vdpa_dev);
	struct device *dev = &pdsv->vdpa_dev.dev;

	dev_dbg(dev, "%s: qid %d\n", __func__, qid);

	hw->vqs[qid].desc_addr = desc_addr;
	hw->vqs[qid].avail_addr = driver_addr;
	hw->vqs[qid].used_addr = device_addr;

	return 0;
}

static void
pds_vdpa_set_vq_num(struct vdpa_device *vdpa_dev, u16 qid, u32 num)
{
	struct pds_vdpa_device *pdsv = vdpa_to_pdsv(vdpa_dev);
	struct pds_vdpa_hw *hw = vdpa_to_hw(vdpa_dev);
	struct device *dev = &pdsv->vdpa_dev.dev;

	dev_dbg(dev, "%s: qid %d num %d\n", __func__, qid, num);
	hw->vqs[qid].q_len = num;
}

static void
pds_vdpa_kick_vq(struct vdpa_device *vdpa_dev, u16 qid)
{
	struct pds_vdpa_device *pdsv = vdpa_to_pdsv(vdpa_dev);
	//struct device *dev = &pdsv->vdpa_dev.dev;

	//dev_info(dev, "%s: qid %d\n", __func__, qid);

	iowrite16(qid, pdsv->hw.vqs[qid].notify);
}

static void
pds_vdpa_set_vq_cb(struct vdpa_device *vdpa_dev, u16 qid,
		   struct vdpa_callback *cb)
{
	struct pds_vdpa_device *pdsv = vdpa_to_pdsv(vdpa_dev);
	struct pds_vdpa_hw *hw = vdpa_to_hw(vdpa_dev);
	struct device *dev = &pdsv->vdpa_dev.dev;

	dev_dbg(dev, "%s: qid %d\n", __func__, qid);
	hw->vqs[qid].event_cb = *cb;
}

static irqreturn_t
pds_vdpa_isr(int irq, void *data)
{
	struct pds_core_intr __iomem *intr_ctrl;
	struct pds_vdpa_device *pdsv;
	struct pds_vdpa_vq_info *vq;

	vq = data;
	pdsv = vq->pdsv;

	if (vq->event_cb.callback)
		vq->event_cb.callback(vq->event_cb.private);

	/* Since we don't actually know how many vq descriptors are
	 * covered in this interrupt cycle, we simply clean all the
	 * credits and re-enable the interrupt.
	 */
	intr_ctrl = (struct pds_core_intr __iomem *)pdsv->vdpa_aux->vdpa_vf->vd_mdev.isr;
	pds_core_intr_clean_flags(&intr_ctrl[vq->intr_index],
				  PDS_CORE_INTR_CRED_REARM);

	return IRQ_HANDLED;
}

static void
pds_vdpa_release_irq(struct pds_vdpa_device *pdsv, int qid)
{
	struct pds_vdpa_intr_info *intrs = pdsv->vdpa_aux->vdpa_vf->intrs;
	struct pci_dev *pdev = pdsv->vdpa_aux->vdpa_vf->pdev;
	struct pds_core_intr __iomem *intr_ctrl;
	int index;

	intr_ctrl = (struct pds_core_intr __iomem *)pdsv->vdpa_aux->vdpa_vf->vd_mdev.isr;
	index = pdsv->hw.vqs[qid].intr_index;
	if (index == VIRTIO_MSI_NO_VECTOR)
		return;

	if (intrs[index].irq == VIRTIO_MSI_NO_VECTOR)
		return;

	if (qid & 0x1) {
		pdsv->hw.vqs[qid].intr_index = VIRTIO_MSI_NO_VECTOR;
	} else {
		pds_core_intr_mask(&intr_ctrl[index], PDS_CORE_INTR_MASK_SET);
		devm_free_irq(&pdev->dev, intrs[index].irq, &pdsv->hw.vqs[qid]);
		pdsv->hw.vqs[qid].intr_index = VIRTIO_MSI_NO_VECTOR;
		intrs[index].irq = VIRTIO_MSI_NO_VECTOR;
	}
}

static void
pds_vdpa_set_vq_ready(struct vdpa_device *vdpa_dev, u16 qid, bool ready)
{
	struct pds_vdpa_device *pdsv = vdpa_to_pdsv(vdpa_dev);
	struct pci_dev *pdev = pdsv->vdpa_aux->vdpa_vf->pdev;
	struct pds_vdpa_hw *hw = vdpa_to_hw(vdpa_dev);
	struct device *dev = &pdsv->vdpa_dev.dev;
	struct pds_core_intr __iomem *intr_ctrl;
	int err;

	dev_dbg(dev, "%s: qid %d ready %d => %d\n",
		 __func__, qid, hw->vqs[qid].ready, ready);
	if (ready == hw->vqs[qid].ready)
		return;

	intr_ctrl = (struct pds_core_intr __iomem *)pdsv->vdpa_aux->vdpa_vf->vd_mdev.isr;
// TODO add lock
	if (ready) {
		struct pds_vdpa_intr_info *intrs = pdsv->vdpa_aux->vdpa_vf->intrs;
		int index = VIRTIO_MSI_NO_VECTOR;
		int i;

		hw->vqs[qid].pdsv = pdsv;
		hw->vqs[qid].qid = qid;

		/*  Tx and Rx queues share interrupts, and they start with
		 *  even numbers, so only find an interrupt for the even numbered
		 *  qid, and let the odd number use what the previous queue got.
		 */
		if (qid & 0x1) {
			int even = qid & ~0x1;
			index = hw->vqs[even].intr_index;
		} else {
			for (i = 0; i < pdsv->vdpa_aux->vdpa_vf->nintrs; i++) {
				if (intrs[i].irq == VIRTIO_MSI_NO_VECTOR) {
					index = i;
					break;
				}
			}
		}

		if (qid & 0x1) {
			hw->vqs[qid].intr_index = index;
		} else if (index != VIRTIO_MSI_NO_VECTOR) {
			int irq;

			irq = pci_irq_vector(pdev, index);
			snprintf(intrs[index].name, sizeof(intrs[index].name),
				 "vdpa-%s-%d", dev_name(dev), index);

			err = devm_request_irq(&pdev->dev, irq, pds_vdpa_isr, 0,
					       intrs[index].name, &hw->vqs[qid]);
			if (err) {
				dev_info(dev, "%s: no irq for qid %d: %pe\n",
					 __func__, qid, ERR_PTR(err));
			} else {
				intrs[index].irq = irq;
				hw->vqs[qid].intr_index = index;
				pds_core_intr_mask(&intr_ctrl[index],
						   PDS_CORE_INTR_MASK_CLEAR);
			}
		} else {
			dev_info(dev, "%s: no intr slot for qid %d\n",
				 __func__, qid);
		}

		/* Pass vq setup info to DSC */
		err = pds_vdpa_cmd_init_vq(pdsv, qid, &hw->vqs[qid]);
		if (err) {
			pds_vdpa_release_irq(pdsv, qid);
			ready = false;
		}
	} else {
		pds_vdpa_release_irq(pdsv, qid);
		(void) pds_vdpa_cmd_reset_vq(pdsv, qid);
	}

	hw->vqs[qid].ready = ready;
// TODO add unlock
}

static bool
pds_vdpa_get_vq_ready(struct vdpa_device *vdpa_dev, u16 qid)
{
	struct pds_vdpa_hw *hw = vdpa_to_hw(vdpa_dev);

	return hw->vqs[qid].ready;
}

static int
pds_vdpa_set_vq_state(struct vdpa_device *vdpa_dev, u16 qid,
		      const struct vdpa_vq_state *state)
{
	struct pds_vdpa_device *pdsv = vdpa_to_pdsv(vdpa_dev);
	struct pds_vdpa_hw *hw = vdpa_to_hw(vdpa_dev);
	struct device *dev = &pdsv->vdpa_dev.dev;

	dev_dbg(dev, "%s: qid %d avail_index %d\n",
		 __func__, qid, state->split.avail_index);

	hw->vqs[qid].used_idx = state->split.avail_index;
	hw->vqs[qid].avail_idx = state->split.avail_index;

	return 0;
}

static int
pds_vdpa_get_vq_state(struct vdpa_device *vdpa_dev, u16 qid,
		      struct vdpa_vq_state *state)
{
	struct pds_vdpa_hw *hw = vdpa_to_hw(vdpa_dev);

	// is there a need to check the actual status in FW?
	state->split.avail_index = hw->vqs[qid].avail_idx;

	return 0;
}

static struct vdpa_notification_area
pds_vdpa_get_vq_notification(struct vdpa_device *vdpa_dev, u16 qid)
{
	struct pds_vdpa_device *pdsv = vdpa_to_pdsv(vdpa_dev);
	struct pds_vdpa_hw *hw = vdpa_to_hw(vdpa_dev);
	struct virtio_pci_modern_device *vd_mdev;
	struct device *dev = &pdsv->vdpa_dev.dev;
	struct vdpa_notification_area area;

	dev_dbg(dev, "%s: qid %d\n", __func__, qid);

	area.addr = hw->vqs[qid].notify_pa;

	vd_mdev = &pdsv->vdpa_aux->vdpa_vf->vd_mdev;
	if (!vd_mdev->notify_offset_multiplier)
		area.size = PAGE_SIZE;
	else
		area.size = vd_mdev->notify_offset_multiplier;

	return area;
}

static int
pds_vdpa_get_vq_irq(struct vdpa_device *vdpa_dev, u16 qid)
{
	struct pds_vdpa_device *pdsv = vdpa_to_pdsv(vdpa_dev);
	struct pds_vdpa_hw *hw = vdpa_to_hw(vdpa_dev);
	struct device *dev = &pdsv->vdpa_dev.dev;
	int irq = VIRTIO_MSI_NO_VECTOR;
	int index;

	if (pdsv->vdpa_aux->vdpa_vf->intrs) {
		index = hw->vqs[qid].intr_index;
		irq = pdsv->vdpa_aux->vdpa_vf->intrs[index].irq;
	}

	dev_dbg(dev, "%s: qid %d index %d irq %d\n",
		 __func__, qid, hw->vqs[qid].intr_index, irq);

	return irq;
}

static u32
pds_vdpa_get_vq_align(struct vdpa_device *vdpa_dev)
{
	struct pds_vdpa_device *pdsv = vdpa_to_pdsv(vdpa_dev);
	struct device *dev = &pdsv->vdpa_dev.dev;

	dev_dbg(dev, "%s: %lu\n", __func__, PAGE_SIZE);

	return PAGE_SIZE;
}

static u32
pds_vdpa_get_vq_group(struct vdpa_device *vdpa_dev, u16 idx)
{
	return 0;
}

static u64
pds_vdpa_get_device_features(struct vdpa_device *vdpa_dev)
{
	struct pds_vdpa_device *pdsv = vdpa_to_pdsv(vdpa_dev);

	return le64_to_cpu(pdsv->vdpa_aux->ident.hw_features);
}

static int
pds_vdpa_set_driver_features(struct vdpa_device *vdpa_dev, u64 features)
{
	struct pds_vdpa_device *pdsv = vdpa_to_pdsv(vdpa_dev);
	struct pds_vdpa_hw *hw = vdpa_to_hw(vdpa_dev);
	struct device *dev = &pdsv->vdpa_dev.dev;
	u64 nego_features;
	u64 set_features;
	u64 missing;
	int err;

	if (!(features & BIT_ULL(VIRTIO_F_ACCESS_PLATFORM)) && features) {
		dev_err(dev, "VIRTIO_F_ACCESS_PLATFORM is not negotiated\n");
		return -EOPNOTSUPP;
	}

	hw->req_features = features;

	/* Check for valid feature bits */
	nego_features = features & le64_to_cpu(pdsv->vdpa_aux->ident.hw_features);
	missing = hw->req_features & ~nego_features;
	if (missing) {
		dev_err(dev, "Can't support all requested features in %#llx, missing %#llx features\n",
			hw->req_features, missing);
		return -EOPNOTSUPP;
	}

	dev_dbg(dev, "%s: %#llx => %#llx\n",
		 __func__, hw->actual_features, nego_features);

	if (hw->actual_features == nego_features)
		return 0;

	/* Update hw feature configuration, strip MAC bit if locally set */
	if (pdsv->vdpa_aux->local_mac_bit)
		set_features = nego_features & ~BIT_ULL(VIRTIO_NET_F_MAC);
	else
		set_features = nego_features;
	err = pds_vdpa_cmd_set_features(pdsv, set_features);
	if (!err)
		hw->actual_features = nego_features;

	return err;
}

static u64
pds_vdpa_get_driver_features(struct vdpa_device *vdpa_dev)
{
	struct pds_vdpa_hw *hw = vdpa_to_hw(vdpa_dev);

	return hw->actual_features;
}

static void
pds_vdpa_set_config_cb(struct vdpa_device *vdpa_dev, struct vdpa_callback *cb)
{
	struct pds_vdpa_device *pdsv = vdpa_to_pdsv(vdpa_dev);
	struct pds_vdpa_hw *hw = vdpa_to_hw(vdpa_dev);
	struct device *dev = &pdsv->vdpa_dev.dev;

	dev_dbg(dev, "%s:\n", __func__);
	hw->config_cb.callback = cb->callback;
	hw->config_cb.private = cb->private;
}

static u16
pds_vdpa_get_vq_num_max(struct vdpa_device *vdpa_dev)
{
	struct pds_vdpa_device *pdsv = vdpa_to_pdsv(vdpa_dev);
	u32 max_qlen;

	max_qlen = min_t(u32, PDS_VDPA_MAX_QLEN,
			      1 << le16_to_cpu(pdsv->vdpa_aux->ident.max_qlen));

	return (u16)max_qlen;
}

static u32
pds_vdpa_get_device_id(struct vdpa_device *vdpa_dev)
{
	return VIRTIO_ID_NET;
}

static u32
pds_vdpa_get_vendor_id(struct vdpa_device *vdpa_dev)
{
	return PCI_VENDOR_ID_PENSANDO;
}

static u8
pds_vdpa_get_status(struct vdpa_device *vdpa_dev)
{
	struct pds_vdpa_hw *hw = vdpa_to_hw(vdpa_dev);

	return hw->status;
}

static void
pds_vdpa_set_status(struct vdpa_device *vdpa_dev, u8 status)
{
	struct pds_vdpa_device *pdsv = vdpa_to_pdsv(vdpa_dev);
	struct pds_vdpa_hw *hw = vdpa_to_hw(vdpa_dev);
	struct device *dev = &pdsv->vdpa_dev.dev;
	int err;

	dev_dbg(dev, "%s: %#x => %#x\n", __func__, hw->status, status);

	if (hw->status == status)
		return;

	/* If the DRIVER_OK bit turns on, time to start the queues */
	if ((status ^ hw->status) & VIRTIO_CONFIG_S_DRIVER_OK) {
		if (status & VIRTIO_CONFIG_S_DRIVER_OK) {
			err = pds_vdpa_setup_driver(pdsv);
			if (err) {
				dev_err(dev, "failed to setup driver: %pe\n", ERR_PTR(err));
				status = hw->status | VIRTIO_CONFIG_S_FAILED;
			}
		} else {
			dev_warn(dev, "did not expect DRIVER_OK to be cleared\n");
		}
	}

	err = pds_vdpa_cmd_set_status(pdsv, status);
	if (!err)
		hw->status = status;
}

static int
pds_vdpa_reset(struct vdpa_device *vdpa_dev)
{
	struct pds_vdpa_device *pdsv = vdpa_to_pdsv(vdpa_dev);
	struct pds_vdpa_hw *hw = vdpa_to_hw(vdpa_dev);
	struct device *dev = &pdsv->vdpa_dev.dev;
	int i;

	dev_dbg(dev, "%s:\n", __func__);

	if (hw->status == 0)
		return 0;

	if (hw->status & VIRTIO_CONFIG_S_DRIVER_OK) {

		/* Reset the vqs */
		for (i = 0; i < hw->num_vqs; i++) {
			pds_vdpa_release_irq(pdsv, i);
			(void) pds_vdpa_cmd_reset_vq(pdsv, i);

			memset(&pdsv->hw.vqs[i], 0, sizeof(pdsv->hw.vqs[0]));
			pdsv->hw.vqs[i].ready = false;
		}
	}

	hw->status = 0;
	(void) pds_vdpa_cmd_set_status(pdsv, 0);

	return 0;
}

static size_t
pds_vdpa_get_config_size(struct vdpa_device *vdpa_dev)
{
	return sizeof(struct virtio_net_config);
}

static void
pds_vdpa_get_config(struct vdpa_device *vdpa_dev,
		    unsigned int offset,
		    void *buf, unsigned int len)
{
	struct pds_vdpa_device *pdsv = vdpa_to_pdsv(vdpa_dev);

	if (offset + len <= sizeof(struct virtio_net_config))
		memcpy(buf, (u8 *)&pdsv->vn_config + offset, len);
}

static void
pds_vdpa_set_config(struct vdpa_device *vdpa_dev,
		    unsigned int offset, const void *buf,
		    unsigned int len)
{
	struct pds_vdpa_device *pdsv = vdpa_to_pdsv(vdpa_dev);
	struct device *dev = &pdsv->vdpa_dev.dev;

	dev_warn(dev, "%s: Unexpected call - offset %d len %d\n", __func__, offset, len);

	/* In the virtio_net context, this callback seems to only be
	 * called in drivers supporting the older non-VERSION_1 API,
	 * so we can leave this an empty function, but we need  to
	 * define the function in case it does get called, as there
	 * are currently no checks for existence before calling in
	 * that path.
	 *
	 * The implementation would be something like:
	 * if (offset + len <= sizeof(struct virtio_net_config))
	 *	memcpy((u8 *)&pdsv->vn_config + offset, buf, len);
	 */
}

static const struct vdpa_config_ops pds_vdpa_ops = {
	.set_vq_address		= pds_vdpa_set_vq_address,
	.set_vq_num		= pds_vdpa_set_vq_num,
	.kick_vq		= pds_vdpa_kick_vq,
	.set_vq_cb		= pds_vdpa_set_vq_cb,
	.set_vq_ready		= pds_vdpa_set_vq_ready,
	.get_vq_ready		= pds_vdpa_get_vq_ready,
	.set_vq_state		= pds_vdpa_set_vq_state,
	.get_vq_state		= pds_vdpa_get_vq_state,
	.get_vq_notification	= pds_vdpa_get_vq_notification,
	.get_vq_irq		= pds_vdpa_get_vq_irq,
	.get_vq_align		= pds_vdpa_get_vq_align,
	.get_vq_group		= pds_vdpa_get_vq_group,

	.get_device_features	= pds_vdpa_get_device_features,
	.set_driver_features	= pds_vdpa_set_driver_features,
	.get_driver_features	= pds_vdpa_get_driver_features,
	.set_config_cb		= pds_vdpa_set_config_cb,
	.get_vq_num_max		= pds_vdpa_get_vq_num_max,
/*	.get_vq_num_min (optional) */
	.get_device_id		= pds_vdpa_get_device_id,
	.get_vendor_id		= pds_vdpa_get_vendor_id,
	.get_status		= pds_vdpa_get_status,
	.set_status		= pds_vdpa_set_status,
	.reset			= pds_vdpa_reset,
	.get_config_size	= pds_vdpa_get_config_size,
	.get_config		= pds_vdpa_get_config,
	.set_config		= pds_vdpa_set_config,

/*	.get_generation (optional) */
/*	.get_iova_range (optional) */
/*	.set_group_asid */
/*	.set_map (optional) */
/*	.dma_map (optional) */
/*	.dma_unmap (optional) */
/*	.free (optional) */
};
static struct virtio_device_id pds_vdpa_id_table[] = {
	{VIRTIO_ID_NET, VIRTIO_DEV_ANY_ID},
	{0},
};

static int
pds_vdpa_dev_add(struct vdpa_mgmt_dev *mdev, const char *name,
		 const struct vdpa_dev_set_config *add_config)
{
	struct pds_vdpa_aux *vdpa_aux;
	struct pds_vdpa_device *pdsv;
	struct vdpa_mgmt_dev *mgmt;
	u16 fw_max_vqs, vq_pairs;
	struct device *dma_dev;
	struct pds_vdpa_hw *hw;
	struct pci_dev *pdev;
	struct device *dev;
	u8 mac[ETH_ALEN];
	int err;
	int i;

	vdpa_aux = container_of(mdev, struct pds_vdpa_aux, vdpa_mdev);
	dev = &vdpa_aux->padev->aux_dev.dev;
	mgmt = &vdpa_aux->vdpa_mdev;

	if (vdpa_aux->pdsv) {
		dev_warn(dev, "Multiple vDPA devices on a VF is not supported.\n");
		return -EOPNOTSUPP;
	}

	pdsv = vdpa_alloc_device(struct pds_vdpa_device, vdpa_dev,
				 dev, &pds_vdpa_ops, 1, 1, name, false);
	if (IS_ERR(pdsv)) {
		dev_err(dev, "Failed to allocate vDPA structure: %pe\n", pdsv);
		return PTR_ERR(pdsv);
	}

	vdpa_aux->pdsv = pdsv;
	pdsv->vdpa_aux = vdpa_aux;
	pdsv->vdpa_aux->padev->priv = pdsv;

	pdev = vdpa_aux->vdpa_vf->pdev;
	pdsv->vdpa_dev.dma_dev = &pdev->dev;
	dma_dev = pdsv->vdpa_dev.dma_dev;
	hw = &pdsv->hw;

	pdsv->vn_config_pa = dma_map_single(dma_dev, &pdsv->vn_config,
					    sizeof(pdsv->vn_config), DMA_FROM_DEVICE);
	if (dma_mapping_error(dma_dev, pdsv->vn_config_pa)) {
		dev_err(dma_dev, "Failed to map vn_config space\n");
		pdsv->vn_config_pa = 0;
		err = -ENOMEM;
		goto err_out;
	}

	err = pds_vdpa_init_hw(pdsv);
	if (err) {
		dev_err(dev, "Failed to init hw: %pe\n", ERR_PTR(err));
		goto err_unmap;
	}

	fw_max_vqs = le16_to_cpu(pdsv->vdpa_aux->ident.max_vqs);

	/* Make sure we have the queues being requested */
	vq_pairs = 0;
	if (add_config->mask & (1 << VDPA_ATTR_DEV_NET_CFG_MAX_VQP))
		vq_pairs = add_config->net.max_vq_pairs;
	else
		vq_pairs = 1;

	hw->num_vqs = 2 * vq_pairs;
	if (mgmt->supported_features & BIT_ULL(VIRTIO_NET_F_CTRL_VQ))
		hw->num_vqs++;

	if (hw->num_vqs > fw_max_vqs) {
		dev_err(dev, "%s: queue count requested %u greater than max %u\n",
			 __func__, hw->num_vqs, fw_max_vqs);
		err = -ENOSPC;
		goto err_unmap;
	}

#ifndef PDS_VDPA_CFG_MAX_VQP
	// TODO: If we don't update net_config->max_virtqueue_pairs,
	// the virtio_net code will choke when it tries to
	// initialize.
	// If we do update the net_config, though, the CVQ
	// will not be at the expected vqid, and FW init will fail.
	if (hw->num_vqs != fw_max_vqs) {
		hw->num_vqs = fw_max_vqs;
		dev_warn(dev, "%s: XXX HACK: overriding num_vqs to %u\n",
			 __func__, hw->num_vqs);
	}
#endif

	if (hw->num_vqs != fw_max_vqs) {
		err = pds_vdpa_cmd_set_max_vq_pairs(pdsv, vq_pairs);
		if (err) {
			dev_err(dev, "Failed to update max_vq_pairs: %pe\n",
				ERR_PTR(err));
			goto err_unmap;
		}
	}

	/* Set a mac, either from the user config if provided
	 * or set a random mac if default is 00:..:00
	 */
	if (add_config->mask & (1 << VDPA_ATTR_DEV_NET_CFG_MACADDR)) {
		ether_addr_copy(mac, add_config->net.mac);
		(void) pds_vdpa_cmd_set_mac(pdsv, mac);
	} else if (is_zero_ether_addr(pdsv->vn_config.mac)) {
		eth_random_addr(mac);
		(void) pds_vdpa_cmd_set_mac(pdsv, mac);
	}

	for (i = 0; i < hw->num_vqs; i++) {
		hw->vqs[i].intr_index = VIRTIO_MSI_NO_VECTOR;
		hw->vqs[i].notify = vp_modern_map_vq_notify(&pdsv->vdpa_aux->vdpa_vf->vd_mdev,
							    i, &hw->vqs[i].notify_pa);
	}

	pdsv->vdpa_dev.mdev = &vdpa_aux->vdpa_mdev;

	/* We use the _vdpa_register_device() call rather than the
	 * vdpa_register_device() to avoid a deadlock because this
	 * dev_add() is called with the vdpa_dev_lock already set
	 * by vdpa_nl_cmd_dev_add_set_doit()
	 */
	err = _vdpa_register_device(&pdsv->vdpa_dev, hw->num_vqs);
	if (err) {
		dev_err(dev, "Failed to register to vDPA bus: %pe\n", ERR_PTR(err));
		goto err_unmap;
	}

	pds_vdpa_debugfs_add_vdpadev(pdsv);
	dev_info(&pdsv->vdpa_dev.dev, "Added with mac %pM\n", mac);

	return 0;

err_unmap:
	dma_unmap_single(dma_dev, pdsv->vn_config_pa,
			 sizeof(pdsv->vn_config), DMA_FROM_DEVICE);
err_out:
	put_device(&pdsv->vdpa_dev.dev);
	vdpa_aux->pdsv = NULL;
	return err;
}

static void
pds_vdpa_dev_del(struct vdpa_mgmt_dev *mdev, struct vdpa_device *vdpa_dev)
{
	struct pds_vdpa_device *pdsv = vdpa_to_pdsv(vdpa_dev);
	struct pds_vdpa_aux *vdpa_aux;

	dev_info(&vdpa_dev->dev, "Removed\n");

	vdpa_aux = container_of(mdev, struct pds_vdpa_aux, vdpa_mdev);
	_vdpa_unregister_device(vdpa_dev);
	pds_vdpa_debugfs_del_vdpadev(pdsv);

	if (vdpa_aux->pdsv->vn_config_pa)
		dma_unmap_single(vdpa_dev->dma_dev, vdpa_aux->pdsv->vn_config_pa,
				 sizeof(vdpa_aux->pdsv->vn_config), DMA_FROM_DEVICE);

	vdpa_aux->pdsv = NULL;
}

static const struct vdpa_mgmtdev_ops pds_vdpa_mgmt_dev_ops = {
	.dev_add = pds_vdpa_dev_add,
	.dev_del = pds_vdpa_dev_del
};

int
pds_vdpa_get_mgmt_info(struct pds_vdpa_aux *vdpa_aux)
{
	struct pds_vdpa_pci_device *vdpa_pdev;
	struct pds_vdpa_ident_cmd ident_cmd = {
		.opcode = PDS_VDPA_CMD_IDENT,
		.vf_id = cpu_to_le16(vdpa_aux->vdpa_vf->vf_id),
	};
	struct pds_vdpa_comp ident_comp = {0};
	struct vdpa_mgmt_dev *mgmt;
	struct device *dma_dev;
	dma_addr_t ident_pa;
	struct pci_dev *pdev;
	struct device *dev;
	__le64 mac_bit;
	u16 max_vqs;
	int err;
	int i;

	vdpa_pdev = vdpa_aux->vdpa_vf;
	pdev = vdpa_pdev->pdev;
	dev = &vdpa_aux->padev->aux_dev.dev;
	mgmt = &vdpa_aux->vdpa_mdev;

	/* Get resource info from the device */
	dma_dev = &pdev->dev;
	ident_pa = dma_map_single(dma_dev, &vdpa_aux->ident,
				  sizeof(vdpa_aux->ident), DMA_FROM_DEVICE);
	if (dma_mapping_error(dma_dev, ident_pa)) {
		dev_err(dma_dev, "Failed to map ident space\n");
		return -ENOMEM;
	}

	ident_cmd.ident_pa = cpu_to_le64(ident_pa);
	ident_cmd.len = cpu_to_le32(sizeof(vdpa_aux->ident));
	err = vdpa_aux->padev->ops->adminq_cmd(vdpa_aux->padev, PDS_DEFAULT_ADMINQ,
					       (union pds_core_adminq_cmd *)&ident_cmd,
					       sizeof(ident_cmd),
					       (union pds_core_adminq_comp *)&ident_comp,
					       NULL, NULL, 0);
	dma_unmap_single(dma_dev, ident_pa,
			 sizeof(vdpa_aux->ident), DMA_FROM_DEVICE);
	if (err) {
		dev_err(dev, "Failed to ident hw, status %d: %pe\n",
			ident_comp.status, ERR_PTR(err));
		return err;
	}

	/* The driver adds a default mac address if the device doesn't,
	 * so we need to sure we advertise VIRTIO_NET_F_MAC
	 */
	mac_bit = cpu_to_le64(BIT_ULL(VIRTIO_NET_F_MAC));
	if (!(vdpa_aux->ident.hw_features & mac_bit)) {
		vdpa_aux->ident.hw_features |= mac_bit;
		vdpa_aux->local_mac_bit = true;
	}

	max_vqs = le16_to_cpu(vdpa_aux->ident.max_vqs);
	mgmt->max_supported_vqs = min_t(u16, PDS_VDPA_MAX_QUEUES, max_vqs);
	if (max_vqs > PDS_VDPA_MAX_QUEUES)
		dev_info(dev, "FYI - Device supports more vqs (%d) than driver (%d)\n",
			 max_vqs, PDS_VDPA_MAX_QUEUES);

	mgmt->ops = &pds_vdpa_mgmt_dev_ops;
	mgmt->id_table = pds_vdpa_id_table;
	mgmt->device = dev;
	mgmt->supported_features = le64_to_cpu(vdpa_aux->ident.hw_features);
	mgmt->config_attr_mask = BIT_ULL(VDPA_ATTR_DEV_NET_CFG_MACADDR);
	mgmt->config_attr_mask |= BIT_ULL(VDPA_ATTR_DEV_NET_CFG_MAX_VQP);

	/* Set up interrupts now that we know how many we might want
	 * TX and RX pairs will share interrupts, so halve the vq count
	 * Add another for a control queue if supported
	 */
	vdpa_pdev->nintrs = mgmt->max_supported_vqs / 2;
	if (mgmt->supported_features & BIT_ULL(VIRTIO_NET_F_CTRL_VQ))
		vdpa_pdev->nintrs++;

	err = pci_alloc_irq_vectors(pdev, vdpa_pdev->nintrs, vdpa_pdev->nintrs,
				    PCI_IRQ_MSIX);
	if (err < 0) {
		dev_err(dma_dev, "Couldn't get %d msix vectors: %pe\n",
			vdpa_pdev->nintrs, ERR_PTR(err));
		return err;
	}
	vdpa_pdev->nintrs = err;
	err = 0;

	vdpa_pdev->intrs = devm_kcalloc(&pdev->dev, vdpa_pdev->nintrs,
					sizeof(*vdpa_pdev->intrs),
					GFP_KERNEL);
	if (!vdpa_pdev->intrs) {
		vdpa_pdev->nintrs = 0;
		pci_free_irq_vectors(pdev);
		return -ENOMEM;
	}

	for (i = 0; i < vdpa_pdev->nintrs; i++)
		vdpa_pdev->intrs[i].irq = VIRTIO_MSI_NO_VECTOR;

	return 0;
}

