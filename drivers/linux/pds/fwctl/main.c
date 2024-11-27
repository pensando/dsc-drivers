// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2024 Pensando Systems, Inc */

#include <linux/module.h>
#include <linux/auxiliary_bus.h>
#include <linux/pci.h>
//#include <uapi/fwctl/fwctl.h>
//#include <uapi/fwctl/pds.h>
#include "../include/linux/pds/uapi/fwctl/fwctl.h"
#include <linux/fwctl.h>
#include "../include/linux/pds/uapi/fwctl/pds.h"

//#include <linux/pds/pds_common.h>
#include "../include/linux/pds/pds_common.h"
#include <linux/pds/pds_core_if.h>
//#include <linux/pds/pds_adminq.h>
#include "../include/linux/pds/pds_adminq.h"
#include <linux/pds/pds_auxbus.h>

DEFINE_FREE(kfree_errptr, void *, if (!IS_ERR_OR_NULL(_T)) kfree(_T));
DEFINE_FREE(kvfree_errptr, void *, if (!IS_ERR_OR_NULL(_T)) kvfree(_T));

struct pdsfc_uctx {
	struct fwctl_uctx uctx;
	u32 uctx_caps;
	u32 uctx_uid;
};

struct pdsfc_dev {
	struct fwctl_device fwctl;
	struct pds_auxiliary_dev *padev;
	struct pdsc *pdsc;
	u32 caps;
};
DEFINE_FREE(pdsfc_dev, struct pdsfc_dev *, if (_T) fwctl_put(&_T->fwctl));

static int pdsfc_open_uctx(struct fwctl_uctx *uctx)
{
	struct pdsfc_dev *pdsfc = container_of(uctx->fwctl, struct pdsfc_dev, fwctl);
	struct pdsfc_uctx *pdsfc_uctx = container_of(uctx, struct pdsfc_uctx, uctx);
	struct device *dev = &uctx->fwctl->dev;

	dev_info(dev, "%s: caps = 0x%04x\n", __func__, pdsfc->caps);
	pdsfc_uctx->uctx_caps = pdsfc->caps;

	return 0;
}

static void pdsfc_close_uctx(struct fwctl_uctx *uctx)
{
	struct device *dev = &uctx->fwctl->dev;

	dev_info(dev, "%s: \n", __func__);
}

static void *pdsfc_info(struct fwctl_uctx *uctx, size_t *length)
{
	struct pdsfc_uctx *pdsfc_uctx = container_of(uctx, struct pdsfc_uctx, uctx);
	struct fwctl_info_pds *info;
	struct device *dev = &uctx->fwctl->dev;

	dev_info(dev, "%s: \n", __func__);
	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info)
		return ERR_PTR(-ENOMEM);

	info->uctx_caps = pdsfc_uctx->uctx_caps;

	return info;
}

static void *pdsfc_fw_rpc(struct fwctl_uctx *uctx, enum fwctl_rpc_scope scope,
			  void *in, size_t in_len, size_t *out_len)
{
	struct pdsfc_dev *pdsfc = container_of(uctx->fwctl, struct pdsfc_dev, fwctl);
	struct fwctl_rpc_pds *rpc = (struct fwctl_rpc_pds *)in;
	void *out_payload __free(kfree_errptr) = NULL;
	void *in_payload __free(kfree_errptr) = NULL;
	struct device *dev = &uctx->fwctl->dev;
	union pds_core_adminq_comp comp = {0};
	dma_addr_t out_payload_dma_addr = 0;
	union pds_core_adminq_cmd cmd = {0};
	dma_addr_t in_payload_dma_addr = 0;
	void *out = NULL;
	int ret;

	if (rpc->in.len > 0) {
		in_payload = kzalloc(rpc->in.len, GFP_KERNEL);
		if (!in_payload) {
			dev_err(dev, "Failed to allocate in_payload\n");
			out = ERR_PTR(-ENOMEM);
			goto done;
		}

		if (copy_from_user(in_payload, u64_to_user_ptr(rpc->in.payload), rpc->in.len)) {
			dev_err(dev, "Failed to copy in_payload from user\n");
			out = ERR_PTR(-EFAULT);
			goto done;
		}

		in_payload_dma_addr = dma_map_single(dev->parent, in_payload, rpc->in.len, DMA_TO_DEVICE);
		if (dma_mapping_error(dev->parent, in_payload_dma_addr)) {
			dev_err(dev, "Failed to map in_payload\n");
			out = ERR_PTR(-ENOMEM);
			goto done;
		}
	}

	if (rpc->out.len > 0) {
		out_payload = kzalloc(rpc->out.len, GFP_KERNEL);
		if (!out_payload) {
			dev_err(dev, "Failed to allocate out_payload\n");
			out = ERR_PTR(-ENOMEM);
			goto done;
		}

		out_payload_dma_addr = dma_map_single(dev->parent, out_payload, rpc->out.len, DMA_FROM_DEVICE);
		if (dma_mapping_error(dev->parent, out_payload_dma_addr)) {
			dev_err(dev, "Failed to map out_payload\n");
			out = ERR_PTR(-ENOMEM);
			goto done;
		}
	}

	cmd.fwctl_rpc.opcode = PDS_FWCTL_CMD_RPC;
	cmd.fwctl_rpc.ep = cpu_to_le32(rpc->in.ep);
	cmd.fwctl_rpc.op = cpu_to_le32(rpc->in.op);
	cmd.fwctl_rpc.req_pa = cpu_to_le64(in_payload_dma_addr);
	cmd.fwctl_rpc.req_sz = cpu_to_le32(rpc->in.len);
	cmd.fwctl_rpc.resp_pa = cpu_to_le64(out_payload_dma_addr);
	cmd.fwctl_rpc.resp_sz = cpu_to_le32(rpc->out.len);

	dev_dbg(dev, "%s: opcode %d ep %d op %d"
		" req_pa %llx req_sz %d req_sg %d"
		" resp_pa %llx resp_sz %d resp_sg %d\n",
		__func__, cmd.fwctl_rpc.opcode, rpc->in.ep, rpc->in.op,
		cmd.fwctl_rpc.req_pa, cmd.fwctl_rpc.req_sz, cmd.fwctl_rpc.req_sg_elems,
		cmd.fwctl_rpc.resp_pa, cmd.fwctl_rpc.resp_sz, cmd.fwctl_rpc.resp_sg_elems);

	ret = pds_client_adminq_cmd(pdsfc->padev, &cmd, sizeof(cmd), &comp, 0);
	if (ret) {
		dev_err(dev, "Failed to send adminq cmd\n");
		out = ERR_PTR(ret);
		goto done;
	}

	dev_dbg(dev, "%s: status %d comp_index %d err %d resp_sz %d color %d\n",
		__func__, comp.fwctl_rpc.status, comp.fwctl_rpc.comp_index,
		comp.fwctl_rpc.err, comp.fwctl_rpc.resp_sz,
		comp.fwctl_rpc.color);

	if (copy_to_user(u64_to_user_ptr(rpc->out.payload), out_payload, rpc->out.len)) {
		dev_err(dev, "Failed to copy out_payload to user\n");
		out = ERR_PTR(-EFAULT);
		goto done;
	}

	rpc->out.retval = le32_to_cpu(comp.fwctl_rpc.err);
	*out_len = in_len;
	out = in;

done:
	if (in_payload_dma_addr)
		dma_unmap_single(dev->parent, in_payload_dma_addr, rpc->in.len, DMA_TO_DEVICE);

	if (out_payload_dma_addr)
		dma_unmap_single(dev->parent, out_payload_dma_addr, rpc->out.len, DMA_FROM_DEVICE);

	return out;
}

static const struct fwctl_ops pdsfc_ops = {
	.device_type = FWCTL_DEVICE_TYPE_PDS,
	.uctx_size = sizeof(struct pdsfc_uctx),
	.open_uctx = pdsfc_open_uctx,
	.close_uctx = pdsfc_close_uctx,
	.info = pdsfc_info,
	.fw_rpc = pdsfc_fw_rpc,
};

static int pdsfc_probe(struct auxiliary_device *adev,
			 const struct auxiliary_device_id *id)
{
	struct pdsfc_dev *pdsfc __free(pdsfc_dev);
	struct pds_auxiliary_dev *padev;
	struct device *dev = &adev->dev;
	int ret;

	padev = container_of(adev, struct pds_auxiliary_dev, aux_dev);
	pdsfc = fwctl_alloc_device(&padev->vf_pdev->dev, &pdsfc_ops, struct pdsfc_dev, fwctl);
	if (!pdsfc)
		return -ENOMEM;
	pdsfc->padev = padev;

	ret = fwctl_register(&pdsfc->fwctl);
	if (ret)
		return ret;
	auxiliary_set_drvdata(adev, no_free_ptr(pdsfc));

	dev_info(dev, "Loaded\n");

	return 0;
}

static void pdsfc_remove(struct auxiliary_device *adev)
{
	struct pdsfc_dev *pdsfc  __free(pdsfc_dev) = auxiliary_get_drvdata(adev);
	struct device *dev = &adev->dev;

	dev_info(dev, "%s: \n", __func__);

	fwctl_unregister(&pdsfc->fwctl);

	dev_info(dev, "Removed\n");
}

static const struct auxiliary_device_id pdsfc_id_table[] = {
	{.name = PDS_CORE_DRV_NAME "." PDS_DEV_TYPE_FWCTL_STR },
	{}
};
MODULE_DEVICE_TABLE(auxiliary, pdsfc_id_table);

static struct auxiliary_driver pdsfc_driver = {
	.name = "pds_fwctl",
	.probe = pdsfc_probe,
	.remove = pdsfc_remove,
	.id_table = pdsfc_id_table,
};

module_auxiliary_driver(pdsfc_driver);

MODULE_IMPORT_NS(FWCTL);
MODULE_DESCRIPTION("pds fwctl driver");
MODULE_AUTHOR("Shannon Nelson <shannon.nelson@amd.com>");
MODULE_LICENSE("Dual BSD/GPL");
