// SPDX-License-Identifier: GPL-2.0-only
/* Copyright(c) 2022 Pensando Systems, Inc */

#include <linux/interrupt.h>
#include <linux/pci.h>
#include <linux/io.h>
#include <linux/types.h>
#include <linux/vdpa.h>

#include "pds_intr.h"
#include "pds_core_if.h"
#include "pds_adminq.h"
#include "pds_vdpa.h"
#include "pds_auxbus.h"

#include "vdpa_dev.h"
#include "aux_drv.h"
#include "pci_drv.h"
#include "cmds.h"

static void
pds_vdpa_check_needs_reset(struct pds_vdpa_device *pdsv, int err)
{
	if (err == -ENXIO)
		pdsv->hw.status |= VIRTIO_CONFIG_S_NEEDS_RESET;
}

int
pds_vdpa_init_hw(struct pds_vdpa_device *pdsv)
{
	struct pds_auxiliary_dev *padev = pdsv->vdpa_aux->padev;
	struct device *dev = &padev->aux_dev.dev;
	struct pds_vdpa_init_cmd init_cmd = {
		.opcode = PDS_VDPA_CMD_INIT,
		.vdpa_index = pdsv->hw.vdpa_index,
		.vf_id = cpu_to_le16(pdsv->vdpa_aux->vdpa_vf->vf_id),
		.len = cpu_to_le32(sizeof(pdsv->vn_config)),
		.config_pa = cpu_to_le64(pdsv->vn_config_pa),
	};
	struct pds_vdpa_comp init_comp = {0};
	int err;

	/* Initialize the vdpa/virtio device */
	err = padev->ops->adminq_cmd(padev, PDS_DEFAULT_ADMINQ,
				     (union pds_core_adminq_cmd *)&init_cmd,
				     sizeof(init_cmd),
				     (union pds_core_adminq_comp *)&init_comp,
				     NULL, NULL, 0);
	if (err) {
		dev_err(dev, "Failed to init hw, status %d: %pe\n",
			init_comp.status, ERR_PTR(err));
		pds_vdpa_check_needs_reset(pdsv, err);
	}

	return err;
}

int
pds_vdpa_cmd_reset(struct pds_vdpa_device *pdsv)
{
	struct pds_auxiliary_dev *padev = pdsv->vdpa_aux->padev;
	struct device *dev = &padev->aux_dev.dev;
	struct pds_vdpa_cmd cmd = {
		.opcode = PDS_VDPA_CMD_RESET,
		.vdpa_index = pdsv->hw.vdpa_index,
		.vf_id = cpu_to_le16(pdsv->vdpa_aux->vdpa_vf->vf_id),
	};
	struct pds_vdpa_comp comp = {0};
	int err;

	err = padev->ops->adminq_cmd(padev, PDS_DEFAULT_ADMINQ,
				     (union pds_core_adminq_cmd *)&cmd,
				     sizeof(cmd),
				     (union pds_core_adminq_comp *)&comp,
				     NULL, NULL, 0);
	if (err) {
		dev_err(dev, "Failed to reset hw, status %d: %pe\n",
			comp.status, ERR_PTR(err));
		pds_vdpa_check_needs_reset(pdsv, err);
	}

	return err;
}

int
pds_vdpa_cmd_set_status(struct pds_vdpa_device *pdsv, u8 status)
{
	struct pds_auxiliary_dev *padev = pdsv->vdpa_aux->padev;
	struct device *dev = &padev->aux_dev.dev;
	struct pds_vdpa_status_cmd cmd = {
		.opcode = PDS_VDPA_CMD_STATUS_UPDATE,
		.vdpa_index = pdsv->hw.vdpa_index,
		.vf_id = cpu_to_le16(pdsv->vdpa_aux->vdpa_vf->vf_id),
		.status = status
	};
	struct pds_vdpa_comp comp = {0};
	int err;

	err = padev->ops->adminq_cmd(padev, PDS_DEFAULT_ADMINQ,
				     (union pds_core_adminq_cmd *)&cmd,
				     sizeof(cmd),
				     (union pds_core_adminq_comp *)&comp,
				     NULL, NULL, 0);
	if (err) {
		dev_err(dev, "Failed to set status update %#x, status %d: %pe\n",
			status, comp.status, ERR_PTR(err));
		pds_vdpa_check_needs_reset(pdsv, err);
	}

	return err;
}

int
pds_vdpa_cmd_set_mac(struct pds_vdpa_device *pdsv, u8 *mac)
{
	struct pds_auxiliary_dev *padev = pdsv->vdpa_aux->padev;
	struct device *dev = &padev->aux_dev.dev;
	struct pds_vdpa_setattr_cmd cmd = {
		.opcode = PDS_VDPA_CMD_SET_ATTR,
		.vdpa_index = pdsv->hw.vdpa_index,
		.vf_id = cpu_to_le16(pdsv->vdpa_aux->vdpa_vf->vf_id),
		.attr = PDS_VDPA_ATTR_MAC,
	};
	struct pds_vdpa_comp comp = {0};
	int err;

	ether_addr_copy(cmd.mac, mac);
	err = padev->ops->adminq_cmd(padev, PDS_DEFAULT_ADMINQ,
				     (union pds_core_adminq_cmd *)&cmd,
				     sizeof(cmd),
				     (union pds_core_adminq_comp *)&comp,
				     NULL, NULL, 0);
	if (err) {
		dev_err(dev, "Failed to set mac address %pM, status %d: %pe\n",
			mac, comp.status, ERR_PTR(err));
		pds_vdpa_check_needs_reset(pdsv, err);
	}

	return err;
}

int
pds_vdpa_cmd_set_max_vq_pairs(struct pds_vdpa_device *pdsv, u16 max_vqp)
{
	struct pds_auxiliary_dev *padev = pdsv->vdpa_aux->padev;
	struct device *dev = &padev->aux_dev.dev;
	struct pds_vdpa_setattr_cmd cmd = {
		.opcode = PDS_VDPA_CMD_SET_ATTR,
		.vdpa_index = pdsv->hw.vdpa_index,
		.vf_id = cpu_to_le16(pdsv->vdpa_aux->vdpa_vf->vf_id),
		.attr = PDS_VDPA_ATTR_MAX_VQ_PAIRS,
		.max_vq_pairs = cpu_to_le16(max_vqp),
	};
	struct pds_vdpa_comp comp = {0};
	int err;

	err = padev->ops->adminq_cmd(padev, PDS_DEFAULT_ADMINQ,
				     (union pds_core_adminq_cmd *)&cmd,
				     sizeof(cmd),
				     (union pds_core_adminq_comp *)&comp,
				     NULL, NULL, 0);
	if (err) {
		dev_err(dev, "Failed to set max vq pairs %u, status %d: %pe\n",
			max_vqp, comp.status, ERR_PTR(err));
		pds_vdpa_check_needs_reset(pdsv, err);
	}

	return err;
}

int
pds_vdpa_cmd_init_vq(struct pds_vdpa_device *pdsv, u16 qid,
		     struct pds_vdpa_vq_info *vq_info)
{
	struct pds_auxiliary_dev *padev = pdsv->vdpa_aux->padev;
	struct device *dev = &padev->aux_dev.dev;
	struct pds_vdpa_vq_init_comp comp = {0};
	struct pds_vdpa_vq_init_cmd cmd = {
		.opcode = PDS_VDPA_CMD_VQ_INIT,
		.vdpa_index = pdsv->hw.vdpa_index,
		.vf_id = cpu_to_le16(pdsv->vdpa_aux->vdpa_vf->vf_id),
		.qid = cpu_to_le16(qid),
		.len = cpu_to_le16(ilog2(vq_info->q_len)),
		.desc_addr = cpu_to_le64(vq_info->desc_addr),
		.avail_addr = cpu_to_le64(vq_info->avail_addr),
		.used_addr = cpu_to_le64(vq_info->used_addr),
		.intr_index = cpu_to_le16(vq_info->intr_index),
	};
	int err;

	dev_dbg(dev, "%s: qid %d len %d desc_addr %#llx avail_addr %#llx used_addr %#llx intr_index %d\n",
		 __func__, qid, ilog2(vq_info->q_len),
		 vq_info->desc_addr, vq_info->avail_addr,
		 vq_info->used_addr, vq_info->intr_index);

	err = padev->ops->adminq_cmd(padev, PDS_DEFAULT_ADMINQ,
				     (union pds_core_adminq_cmd *)&cmd,
				     sizeof(cmd),
				     (union pds_core_adminq_comp *)&comp,
				     NULL, NULL, 0);
	if (err) {
		dev_err(dev, "Failed to init vq %d, status %d: %pe\n",
			qid, comp.status, ERR_PTR(err));
		pds_vdpa_check_needs_reset(pdsv, err);
	} else {
		vq_info->hw_qtype = comp.hw_qtype;
		vq_info->hw_qindex = le16_to_cpu(comp.hw_qindex);
	}

	return err;
}

int
pds_vdpa_cmd_reset_vq(struct pds_vdpa_device *pdsv, u16 qid)
{
	struct pds_auxiliary_dev *padev = pdsv->vdpa_aux->padev;
	struct device *dev = &padev->aux_dev.dev;
	struct pds_vdpa_vq_reset_cmd cmd = {
		.opcode = PDS_VDPA_CMD_VQ_RESET,
		.vdpa_index = pdsv->hw.vdpa_index,
		.vf_id = cpu_to_le16(pdsv->vdpa_aux->vdpa_vf->vf_id),
		.qid = cpu_to_le16(qid),
	};
	struct pds_vdpa_comp comp = {0};
	int err;

	err = padev->ops->adminq_cmd(padev, PDS_DEFAULT_ADMINQ,
				     (union pds_core_adminq_cmd *)&cmd,
				     sizeof(cmd),
				     (union pds_core_adminq_comp *)&comp,
				     NULL, NULL, 0);
	if (err) {
		dev_err(dev, "Failed to reset vq %d, status %d: %pe\n",
			qid, comp.status, ERR_PTR(err));
		pds_vdpa_check_needs_reset(pdsv, err);
	}

	return err;
}

int
pds_vdpa_cmd_set_features(struct pds_vdpa_device *pdsv, u64 features)
{
	struct pds_auxiliary_dev *padev = pdsv->vdpa_aux->padev;
	struct device *dev = &padev->aux_dev.dev;
	struct pds_vdpa_set_features_cmd cmd = {
		.opcode = PDS_VDPA_CMD_SET_FEATURES,
		.vdpa_index = pdsv->hw.vdpa_index,
		.vf_id = cpu_to_le16(pdsv->vdpa_aux->vdpa_vf->vf_id),
		.features = cpu_to_le64(features),
	};
	struct pds_vdpa_comp comp = {0};
	int err;

	err = padev->ops->adminq_cmd(padev, PDS_DEFAULT_ADMINQ,
				     (union pds_core_adminq_cmd *)&cmd,
				     sizeof(cmd),
				     (union pds_core_adminq_comp *)&comp,
				     NULL, NULL, 0);
	if (err) {
		dev_err(dev, "Failed to set features %#llx, status %d: %pe\n",
			features, comp.status, ERR_PTR(err));
		pds_vdpa_check_needs_reset(pdsv, err);
	}

	return err;
}
