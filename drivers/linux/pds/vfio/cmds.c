// SPDX-License-Identifier: GPL-2.0-only
/* Copyright(c) 2022 Pensando Systems, Inc */

#include <linux/interrupt.h>
#include <linux/pci.h>
#include <linux/io.h>
#include <linux/types.h>

#include "pds_intr.h"
#include "pds_core_if.h"
#include "pds_adminq.h"
#include "pds_lm.h"
#include "pds_auxbus.h"

#include "vfio_dev.h"
#include "aux_drv.h"

int
pds_vfio_register_client_cmd(struct pds_vfio_pci_device *pds_vfio)
{
	struct pds_vfio_aux *vfio_aux = pds_vfio->vfio_aux;
	struct pds_auxiliary_dev *padev = vfio_aux->padev;

	return padev->ops->register_client(padev, &vfio_aux->padrv);
}

void
pds_vfio_unregister_client_cmd(struct pds_vfio_pci_device *pds_vfio)
{
	struct pds_auxiliary_dev *padev = pds_vfio->vfio_aux->padev;

	padev->ops->unregister_client(padev);
}

int
pds_vfio_dirty_status_cmd(struct pds_vfio_pci_device *pds_vfio,
			  u64 regions_dma, u8 *max_regions,
			  u8 *num_regions)
{
	struct pds_auxiliary_dev *padev = pds_vfio->vfio_aux->padev;
	struct pci_dev *pdev = pds_vfio->pdev;
	struct pds_lm_dirty_status_cmd cmd = {
		.opcode = PDS_LM_CMD_DIRTY_STATUS,
		.vf_id = cpu_to_le16(pds_vfio->vf_id),
	};
	struct pds_lm_dirty_status_comp comp = {0};
	int err;

	dev_dbg(&pdev->dev, "vf%d: Dirty status\n", pds_vfio->vf_id);

	cmd.regions_dma = cpu_to_le64(regions_dma);
	cmd.max_regions = *max_regions;

	err = padev->ops->adminq_cmd(padev, PDS_DEFAULT_ADMINQ,
				     (union pds_core_adminq_cmd *)&cmd,
				     sizeof(cmd),
				     (union pds_core_adminq_comp *)&comp, NULL,
				     NULL, 0);
	if (err) {
		dev_err(&pdev->dev, "failed to get dirty status: %pe\n",
			ERR_PTR(err));
		return err;
	}

	/* only support seq_ack approach for now */
	if (!(le32_to_cpu(comp.bmp_type_mask) &
	      BIT(PDS_LM_DIRTY_BMP_TYPE_SEQ_ACK))) {
		dev_err(&pdev->dev, "Dirty bitmap tracking SEQ_ACK not supported\n");
		return -EOPNOTSUPP;
	}

	*num_regions = comp.num_regions;
	*max_regions = comp.max_regions;

	dev_dbg(&pdev->dev, "Page Tracking Status command successful, max_regions: %d, num_regions: %d, bmp_type: %s\n",
		*max_regions, *num_regions, "PDS_LM_DIRTY_BMP_TYPE_SEQ_ACK");

	return 0;
}

int
pds_vfio_dirty_enable_cmd(struct pds_vfio_pci_device *pds_vfio,
			  u64 regions_dma, u8 num_regions)
{
	struct pds_auxiliary_dev *padev = pds_vfio->vfio_aux->padev;
	struct pds_lm_dirty_enable_cmd cmd = {
		.opcode = PDS_LM_CMD_DIRTY_ENABLE,
		.vf_id = cpu_to_le16(pds_vfio->vf_id),
	};
	struct pds_lm_dirty_status_comp comp = {0};
	struct pci_dev *pdev = pds_vfio->pdev;
	int err;

	cmd.regions_dma = cpu_to_le64(regions_dma);
	cmd.bmp_type = PDS_LM_DIRTY_BMP_TYPE_SEQ_ACK;
	cmd.num_regions = num_regions;

	err = padev->ops->adminq_cmd(padev, PDS_DEFAULT_ADMINQ,
				     (union pds_core_adminq_cmd *)&cmd,
				     sizeof(cmd),
				     (union pds_core_adminq_comp *)&comp, NULL,
				     NULL, 0);
	if (err) {
		dev_err(&pdev->dev, "failed dirty tracking enable: %pe\n",
			ERR_PTR(err));
		return err;
	}

	return 0;
}

int
pds_vfio_dirty_disable_cmd(struct pds_vfio_pci_device *pds_vfio)
{
	struct pds_auxiliary_dev *padev = pds_vfio->vfio_aux->padev;
	struct pds_lm_dirty_disable_cmd cmd = {
		.opcode = PDS_LM_CMD_DIRTY_DISABLE,
		.vf_id = cpu_to_le16(pds_vfio->vf_id),
	};
	struct pds_lm_dirty_status_comp comp = {0};
	struct pci_dev *pdev = pds_vfio->pdev;
	int err;

	err = padev->ops->adminq_cmd(padev, PDS_DEFAULT_ADMINQ,
				     (union pds_core_adminq_cmd *)&cmd,
				     sizeof(cmd),
				     (union pds_core_adminq_comp *)&comp, NULL,
				     NULL, 0);
	if (err || comp.num_regions != 0) {
		dev_err(&pdev->dev, "failed dirty tracking disable: %pe, num_regions %d\n",
			ERR_PTR(err), comp.num_regions);
		return err;
	}

	return 0;
}

int
pds_vfio_dirty_seq_ack_cmd(struct pds_vfio_pci_device *pds_vfio,
			   u64 sgl_dma, u16 num_sge, u32 offset,
			   u32 total_len, bool read_seq)
{
	const char *cmd_type_str = read_seq ? "read_seq" : "write_ack";
	struct pds_auxiliary_dev *padev = pds_vfio->vfio_aux->padev;
	struct pds_lm_dirty_seq_ack_cmd cmd = {
		.vf_id = cpu_to_le16(pds_vfio->vf_id),
	};
	struct pci_dev *pdev = pds_vfio->pdev;
	struct pds_lm_comp comp = {0};
	int err;

	if (read_seq)
		cmd.opcode = PDS_LM_CMD_DIRTY_READ_SEQ;
	else
		cmd.opcode = PDS_LM_CMD_DIRTY_WRITE_ACK;

	cmd.sgl_addr = cpu_to_le64(sgl_dma);
	cmd.num_sge = cpu_to_le16(num_sge);
	cmd.len_bytes = cpu_to_le32(total_len);
	cmd.off_bytes = cpu_to_le32(offset);

	err = padev->ops->adminq_cmd(padev, PDS_DEFAULT_ADMINQ,
				     (union pds_core_adminq_cmd *)&cmd,
				     sizeof(cmd),
				     (union pds_core_adminq_comp *)&comp, NULL,
				     NULL, 0);
	if (err) {
		dev_err(&pdev->dev, "failed cmd Page Tracking %s: %pe\n",
			cmd_type_str, ERR_PTR(err));
		return err;
	}

	return 0;
}

#define SUSPEND_TIMEOUT			5    // 5s
#define SUSPEND_CHECK_INTERVAL_MS	1

static int
pds_vfio_suspend_wait_device_cmd(struct pds_vfio_pci_device *pds_vfio)
{
	DECLARE_COMPLETION_ONSTACK(wait_completion);
	struct pds_lm_suspend_status_cmd cmd = {
		.opcode = PDS_LM_CMD_SUSPEND_STATUS,
		.vf_id	= cpu_to_le16(pds_vfio->vf_id),
	};
	struct pds_lm_comp comp = { 0 };
	struct pci_dev *pdev	= pds_vfio->pdev;
	struct pds_auxiliary_dev *padev;
	unsigned long time_limit;
	unsigned long time_start;
	unsigned long time_done;
	int err = 0;

	time_start = jiffies;
	time_limit = time_start + HZ * SUSPEND_TIMEOUT;
	do {
		padev = pds_vfio->vfio_aux->padev;
		err = padev->ops->adminq_cmd(padev, PDS_DEFAULT_ADMINQ,
					     (union pds_core_adminq_cmd *)&cmd,
					     sizeof(cmd),
					     (union pds_core_adminq_comp *)&comp,
					     NULL, NULL, PDS_AQ_FLAG_FASTPOLL);

		if (err != -EAGAIN)
			break;

		if (wait_for_completion_timeout(&wait_completion,
						msecs_to_jiffies(SUSPEND_CHECK_INTERVAL_MS)))
			break;
	} while (time_before(jiffies, time_limit));

	time_done = jiffies;
	dev_dbg(&pdev->dev, "%s: vf_id%d: Suspend comp received in %d msecs\n",
		__func__, pds_vfio->vf_id,
		jiffies_to_msecs(time_done - time_start));

	/* Check the results */
	if (time_after_eq(time_done, time_limit)) {
		dev_err(&pdev->dev, "%s: vf%d: Suspend comp timeout\n", __func__,
			pds_vfio->vf_id);
		err = -ETIMEDOUT;
	}

	return err;
}

int
pds_vfio_suspend_device_cmd(struct pds_vfio_pci_device *pds_vfio)
{
	struct pds_lm_suspend_cmd cmd = {
		.opcode = PDS_LM_CMD_SUSPEND,
		.vf_id = cpu_to_le16(pds_vfio->vf_id),
	};
	struct pds_lm_suspend_comp comp = {0};
	struct pci_dev *pdev = pds_vfio->pdev;
	struct pds_auxiliary_dev *padev;
	int err;

	dev_dbg(&pdev->dev, "vf%d: Suspend device\n", pds_vfio->vf_id);

	padev = pds_vfio->vfio_aux->padev;
	err = padev->ops->adminq_cmd(padev, PDS_DEFAULT_ADMINQ,
				     (union pds_core_adminq_cmd *)&cmd,
				     sizeof(cmd),
				     (union pds_core_adminq_comp *)&comp,
				     NULL, NULL, PDS_AQ_FLAG_FASTPOLL);
	if (err) {
		dev_err(&pdev->dev, "vf%d: Suspend failed: %pe\n",
			pds_vfio->vf_id, ERR_PTR(err));
		return err;
	}

	return pds_vfio_suspend_wait_device_cmd(pds_vfio);
}

int
pds_vfio_resume_device_cmd(struct pds_vfio_pci_device *pds_vfio)
{
	struct pds_lm_resume_cmd cmd = {
		.opcode = PDS_LM_CMD_RESUME,
		.vf_id = cpu_to_le16(pds_vfio->vf_id),
	};
	struct pds_lm_comp comp = {0};
	struct pci_dev *pdev = pds_vfio->pdev;
	struct pds_auxiliary_dev *padev;

	dev_dbg(&pdev->dev, "vf%d: Resume device\n", pds_vfio->vf_id);

	padev = pds_vfio->vfio_aux->padev;
	return padev->ops->adminq_cmd(padev, PDS_DEFAULT_ADMINQ,
				     (union pds_core_adminq_cmd *)&cmd,
				     sizeof(cmd),
				     (union pds_core_adminq_comp *)&comp, NULL,
				     NULL, 0);
}

int
pds_vfio_get_lm_status_cmd(struct pds_vfio_pci_device *pds_vfio, u64 *size)
{
	struct pds_lm_status_cmd cmd = {
		.opcode = PDS_LM_CMD_STATUS,
		.vf_id = cpu_to_le16(pds_vfio->vf_id),
	};
	struct pds_lm_status_comp comp = {0};
	struct pci_dev *pdev = pds_vfio->pdev;
	struct pds_auxiliary_dev *padev;
	int err = 0;

	dev_dbg(&pdev->dev, "vf%d: Get migration status\n", pds_vfio->vf_id);

	padev = pds_vfio->vfio_aux->padev;
	err = padev->ops->adminq_cmd(padev, PDS_DEFAULT_ADMINQ,
				     (union pds_core_adminq_cmd *)&cmd,
				     sizeof(cmd),
				     (union pds_core_adminq_comp *)&comp, NULL,
				     NULL, 0);
	if (err)
		return err;

	*size = le64_to_cpu(comp.size);
	return 0;
}

static int
pds_vfio_dma_map_lm_file(struct device *dev, enum dma_data_direction dir,
			 struct pds_vfio_lm_file *lm_file)
{
	struct scatterlist *sg;
	struct pds_lm_sg_elem *sgl, *sge;
	int err = 0;
	int i;

	if (!lm_file)
		return -EINVAL;

	/* dma map file pages */
	err = dma_map_sgtable(dev, &lm_file->sg_table, dir, 0);
	if (err)
		goto err_dma_map_sg;

	lm_file->num_sge = lm_file->sg_table.nents;

	/* alloc sgl */
	sgl = dma_alloc_coherent(dev, lm_file->num_sge *
				 sizeof(struct pds_lm_sg_elem),
				 &lm_file->sgl_addr, GFP_KERNEL);
	if (!sgl) {
		err = -ENOMEM;
		goto err_alloc_sgl;
	}

	lm_file->sgl = sgl;

	/* fill sgl */
	sge = sgl;
	for_each_sgtable_dma_sg(&lm_file->sg_table, sg, i) {
		sge->addr = cpu_to_le64(sg_dma_address(sg));
		sge->len  = cpu_to_le32(sg_dma_len(sg));
		dev_dbg(dev, "addr = %llx, len = %u\n", sge->addr, sge->len);
		sge++;
	}

	return 0;

err_alloc_sgl:
	dma_unmap_sgtable(dev, &lm_file->sg_table, dir, 0);
err_dma_map_sg:
	return err;
}

static void
pds_vfio_dma_unmap_lm_file(struct device *dev, enum dma_data_direction dir,
			   struct pds_vfio_lm_file *lm_file)
{
	if (!lm_file)
		return;

	/* free sgl */
	if (lm_file->sgl) {
		dma_free_coherent(dev, lm_file->num_sge *
				  sizeof(struct pds_lm_sg_elem),
				  lm_file->sgl, lm_file->sgl_addr);
		lm_file->sgl = NULL;
		lm_file->sgl_addr = DMA_MAPPING_ERROR;
		lm_file->num_sge = 0;
	}

	/* dma unmap file pages */
	dma_unmap_sgtable(dev, &lm_file->sg_table, dir, 0);
}

int
pds_vfio_get_lm_state_cmd(struct pds_vfio_pci_device *pds_vfio)
{
	struct pds_lm_save_cmd cmd = {
		.opcode = PDS_LM_CMD_SAVE,
		.vf_id = cpu_to_le16(pds_vfio->vf_id),
	};
	struct pds_vfio_lm_file *lm_file;
	struct pci_dev *pdev = pds_vfio->pdev;
	struct pds_auxiliary_dev *padev;
	struct pds_lm_comp comp = {0};
	int err = 0;

	dev_dbg(&pdev->dev, "vf%d: Get migration state\n", pds_vfio->vf_id);

	lm_file = pds_vfio->save_file;

	padev = pds_vfio->vfio_aux->padev;
	err = pds_vfio_dma_map_lm_file(pds_vfio->coredev, DMA_FROM_DEVICE, lm_file);
	if (err) {
		err = -EIO;
		dev_err(&pdev->dev, "failed to map save migration file\n");
		goto err_dma_map_file;
	}

	cmd.sgl_addr = cpu_to_le64(lm_file->sgl_addr);
	cmd.num_sge = cpu_to_le16(lm_file->num_sge);

	err = padev->ops->adminq_cmd(padev, PDS_DEFAULT_ADMINQ,
				     (union pds_core_adminq_cmd *)&cmd,
				     sizeof(cmd),
				     (union pds_core_adminq_comp *)&comp, NULL,
				     NULL, 0);
	if (err) {
		dev_err(&pdev->dev, "failed to get migration state: %pe\n",
			ERR_PTR(err));
		goto err_cmd;
	}

	pds_vfio_dma_unmap_lm_file(pds_vfio->coredev, DMA_FROM_DEVICE, lm_file);

	return 0;

err_cmd:
	pds_vfio_dma_unmap_lm_file(pds_vfio->coredev, DMA_FROM_DEVICE, lm_file);
err_dma_map_file:
	return err;
}

int
pds_vfio_set_lm_state_cmd(struct pds_vfio_pci_device *pds_vfio)
{
	struct pds_lm_restore_cmd cmd = {
		.opcode = PDS_LM_CMD_RESTORE,
		.vf_id = cpu_to_le16(pds_vfio->vf_id),
	};
	struct pds_vfio_lm_file *lm_file;
	struct pci_dev *pdev = pds_vfio->pdev;
	struct pds_auxiliary_dev *padev;
	struct pds_lm_comp comp = {0};
	int err = 0;

	dev_dbg(&pdev->dev, "vf%d: Set migration state\n", pds_vfio->vf_id);

	lm_file = pds_vfio->restore_file;

	padev = pds_vfio->vfio_aux->padev;
	err = pds_vfio_dma_map_lm_file(pds_vfio->coredev, DMA_TO_DEVICE, lm_file);
	if (err) {
		dev_err(&pdev->dev, "failed to map restore migration file: %pe\n",
			ERR_PTR(err));
		goto err_dma_map_file;
	}

	cmd.sgl_addr = cpu_to_le64(lm_file->sgl_addr);
	cmd.num_sge = cpu_to_le16(lm_file->num_sge);

	err = padev->ops->adminq_cmd(padev, PDS_DEFAULT_ADMINQ,
				     (union pds_core_adminq_cmd *)&cmd,
				     sizeof(cmd),
				     (union pds_core_adminq_comp *)&comp, NULL,
				     NULL, 0);
	if (err) {
		dev_err(&pdev->dev, "failed to set migration state: %pe\n",
			ERR_PTR(err));
		goto err_cmd;
	}

	pds_vfio_dma_unmap_lm_file(pds_vfio->coredev, DMA_TO_DEVICE, lm_file);

	return 0;

err_cmd:
	pds_vfio_dma_unmap_lm_file(pds_vfio->coredev, DMA_TO_DEVICE, lm_file);
err_dma_map_file:
	return err;
}

void
pds_vfio_send_host_vf_lm_status_cmd(struct pds_vfio_pci_device *pds_vfio,
				    enum pds_lm_host_vf_status vf_status)
{
	struct pds_auxiliary_dev *padev = pds_vfio->vfio_aux->padev;
	struct pds_lm_host_vf_status_cmd cmd = {
		.opcode = PDS_LM_CMD_HOST_VF_STATUS,
		.vf_id = cpu_to_le16(pds_vfio->vf_id),
		.status = vf_status,
	};
	struct pci_dev *pdev = pds_vfio->pdev;
	struct pds_lm_comp comp = {0};
	int err;

	dev_dbg(&pdev->dev, "vf%d: Set host VF LM status: %u",
		pds_vfio->vf_id, cmd.status);
	if (vf_status != PDS_LM_STA_IN_PROGRESS &&
	    vf_status != PDS_LM_STA_NONE) {
		dev_warn(&pdev->dev, "Invalid host VF migration status, %d\n",
			 vf_status);
		return;
	}

	err = padev->ops->adminq_cmd(padev, PDS_DEFAULT_ADMINQ,
				     (union pds_core_adminq_cmd *)&cmd,
				     sizeof(cmd),
				     (union pds_core_adminq_comp *)&comp, NULL,
				     NULL, 0);
	if (err)
		dev_warn(&pdev->dev, "failed to send host VF migration status: %pe\n",
			 ERR_PTR(err));
}
