// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2024 Pensando Systems, Inc */

#include <linux/module.h>
#include <linux/auxiliary_bus.h>
#include <linux/pci.h>
#include <linux/vmalloc.h>

/* This is what the eventual upstream code should look like */
#include <uapi/fwctl/fwctl.h>
#include <uapi/fwctl/pds.h>
#include <linux/fwctl.h>

#include <linux/pds/pds_common.h>
#include <linux/pds/pds_core_if.h>
#include <linux/pds/pds_adminq.h>


#include <linux/pds/pds_auxbus.h>

DEFINE_FREE(kfree_errptr, void *, if (!IS_ERR_OR_NULL(_T)) kfree(_T));
DEFINE_FREE(kvfree_errptr, void *, if (!IS_ERR_OR_NULL(_T)) kvfree(_T));

struct pdsfc_uctx {
	struct fwctl_uctx uctx;
	u32 uctx_caps;
	u32 uctx_uid;
};

struct pdsfc_rpc_endpoint_info {
	u32 endpoint;
	dma_addr_t operations_pa;
	struct pds_fwctl_query_data *operations;
	struct mutex lock;
};

struct pdsfc_dev {
	struct fwctl_device fwctl;
	struct pds_auxiliary_dev *padev;
	struct pdsc *pdsc;
	u32 caps;
	dma_addr_t ident_pa;
	struct pds_fwctl_ident *ident;
	dma_addr_t endpoints_pa;
	struct pds_fwctl_query_data *endpoints;
	struct pdsfc_rpc_endpoint_info *endpoint_info;
};
DEFINE_FREE(pdsfc_dev, struct pdsfc_dev *, if (_T) fwctl_put(&_T->fwctl));

static int pdsfc_open_uctx(struct fwctl_uctx *uctx)
{
	struct pdsfc_dev *pdsfc = container_of(uctx->fwctl, struct pdsfc_dev, fwctl);
	struct pdsfc_uctx *pdsfc_uctx = container_of(uctx, struct pdsfc_uctx, uctx);
	struct device *dev = &uctx->fwctl->dev;
	int ret = 0;

	dev_dbg(dev, "%s: caps = 0x%04x\n", __func__, pdsfc->caps);
	pdsfc_uctx->uctx_caps = pdsfc->caps;

	return ret;
}

static void pdsfc_close_uctx(struct fwctl_uctx *uctx)
{
	struct device *dev = &uctx->fwctl->dev;

	dev_dbg(dev, "%s \n", __func__);
}

static void *pdsfc_info(struct fwctl_uctx *uctx, size_t *length)
{
	struct pdsfc_uctx *pdsfc_uctx = container_of(uctx, struct pdsfc_uctx, uctx);
	struct fwctl_info_pds *info;

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info)
		return ERR_PTR(-ENOMEM);

	info->uctx_caps = pdsfc_uctx->uctx_caps;

	return info;
}

static void pdsfc_free_ident(struct pdsfc_dev *pdsfc)
{
	struct device *dev = &pdsfc->fwctl.dev;

	if (pdsfc->ident) {
		dma_free_coherent(dev, sizeof(*pdsfc->ident), pdsfc->ident, pdsfc->ident_pa);
		pdsfc->ident = NULL;
		pdsfc->ident_pa = DMA_MAPPING_ERROR;
	}
}

static int pdsfc_identify(struct pdsfc_dev *pdsfc)
{
	struct device *dev = &pdsfc->fwctl.dev;
	struct pds_fwctl_ident *ident;
	dma_addr_t ident_pa;
	union pds_core_adminq_cmd cmd = {0};
	union pds_core_adminq_comp comp = {0};
	int ret = 0;

	ident = dma_alloc_coherent(dev->parent, sizeof(*ident), &ident_pa, GFP_KERNEL);
	if (dma_mapping_error(dev->parent, ident_pa)) {
		dev_err(dev, "Failed to map ident\n");
		return -ENOMEM;
	}

	cmd.fwctl_ident.opcode = PDS_FWCTL_CMD_IDENT;
	cmd.fwctl_ident.version = 0;
	cmd.fwctl_ident.len = cpu_to_le32(sizeof(*ident));
	cmd.fwctl_ident.ident_pa = cpu_to_le64(ident_pa);

	ret = pds_client_adminq_cmd(pdsfc->padev, &cmd, sizeof(cmd), &comp, 0);
	if (ret) {
		dma_free_coherent(dev->parent, PAGE_SIZE, ident, ident_pa);
		dev_err(dev, "Failed to send adminq cmd\n");
		return -EIO;
	}

	pdsfc->ident = ident;
	pdsfc->ident_pa = ident_pa;

	dev_dbg(dev, "ident: version %u max_req_sz %u max_resp_sz %u max_req_sg_elems %u max_resp_sg_elems %u\n",
		ident->version, ident->max_req_sz, ident->max_resp_sz, ident->max_req_sg_elems, ident->max_resp_sg_elems);

	return 0;
}

static void pdsfc_free_endpoints(struct pdsfc_dev *pdsfc)
{
	struct device *dev = &pdsfc->fwctl.dev;

	if (pdsfc->endpoints) {
		int i;

		for (i = 0; pdsfc->endpoint_info && i < pdsfc->endpoints->num_entries; i++)
			mutex_destroy(&pdsfc->endpoint_info[i].lock);
		vfree(pdsfc->endpoint_info);
		pdsfc->endpoint_info = NULL;
		dma_free_coherent(dev->parent, PAGE_SIZE, pdsfc->endpoints, pdsfc->endpoints_pa);
		pdsfc->endpoints = NULL;
		pdsfc->endpoints_pa = DMA_MAPPING_ERROR;
	}
}

static void pdsfc_free_operations(struct pdsfc_dev *pdsfc)
{
	struct device *dev = &pdsfc->fwctl.dev;
	int i;

	for (i = 0; i < pdsfc->endpoints->num_entries; i++) {
		if (pdsfc->endpoint_info[i].operations) {
			dma_free_coherent(dev->parent, PAGE_SIZE, pdsfc->endpoint_info[i].operations, pdsfc->endpoint_info[i].operations_pa);
			pdsfc->endpoint_info[i].operations = NULL;
			pdsfc->endpoint_info[i].operations_pa = DMA_MAPPING_ERROR;
		}
	}
}

static struct pds_fwctl_query_data *pdsfc_get_endpoints(struct pdsfc_dev *pdsfc, dma_addr_t *pa)
{
	struct device *dev = &pdsfc->fwctl.dev;
	struct pds_fwctl_query_data *data;
	union pds_core_adminq_cmd cmd = {0};
	union pds_core_adminq_comp comp = {0};
	struct pds_fwctl_query_data_endpoint *entries = NULL;
	dma_addr_t data_pa;
	int ret = 0;
	int i;

	data = dma_alloc_coherent(dev->parent, PAGE_SIZE, &data_pa, GFP_KERNEL);
	if (dma_mapping_error(dev, data_pa)) {
		dev_err(dev, "Failed to map endpoint list\n");
		return ERR_PTR(-ENOMEM);
	}

	cmd.fwctl_query.opcode = PDS_FWCTL_CMD_QUERY;
	cmd.fwctl_query.entity = PDS_FWCTL_RPC_ROOT;
	cmd.fwctl_query.version = 0;
	cmd.fwctl_query.query_data_buf_len = cpu_to_le32(PAGE_SIZE);
	cmd.fwctl_query.query_data_buf_pa = cpu_to_le64(data_pa);

	dev_dbg(dev, "cmd: opcode %d entity %d version %d query_data_buf_len %d query_data_buf_pa %llx\n",
		cmd.fwctl_query.opcode, cmd.fwctl_query.entity, cmd.fwctl_query.version,
		le32_to_cpu(cmd.fwctl_query.query_data_buf_len), le64_to_cpu(cmd.fwctl_query.query_data_buf_pa));

	ret = pds_client_adminq_cmd(pdsfc->padev, &cmd, sizeof(cmd), &comp, 0);
	if (ret) {
		dev_err(dev, "Failed to send adminq cmd\n");
		dma_free_coherent(dev->parent, PAGE_SIZE, data, data_pa);
		return ERR_PTR(EIO);
	}

	*pa = data_pa;

	entries = (struct pds_fwctl_query_data_endpoint *)data->entries;
	dev_dbg(dev, "num_entries %d\n", data->num_entries);
	for (i = 0; i < data->num_entries; i++)
		dev_dbg(dev, "endpoint: id %d\n", entries[i].id);

	return data;
}

static int pdsfc_init_endpoints(struct pdsfc_dev *pdsfc)
{
	struct pds_fwctl_query_data_endpoint *ep_entry;
	struct device *dev = &pdsfc->fwctl.dev;
	int i;

	pdsfc->endpoints = pdsfc_get_endpoints(pdsfc, &pdsfc->endpoints_pa);
	if (IS_ERR(pdsfc->endpoints)) {
		dev_err(dev, "Failed to query endpoints\n");
		return PTR_ERR(pdsfc->endpoints);
	}

	pdsfc->endpoint_info = vzalloc(pdsfc->endpoints->num_entries * sizeof(*pdsfc->endpoint_info));
	if (!pdsfc->endpoint_info) {
		dev_err(dev, "Failed to allocate endpoint_info array\n");
		pdsfc_free_endpoints(pdsfc);
		return -ENOMEM;
	}

	ep_entry = (struct pds_fwctl_query_data_endpoint *)pdsfc->endpoints->entries;
	for (i = 0; i < pdsfc->endpoints->num_entries; i++) {
		mutex_init(&pdsfc->endpoint_info[i].lock);
		pdsfc->endpoint_info[i].endpoint = ep_entry[i].id;
	}

	return 0;
}

static struct pds_fwctl_query_data *pdsfc_get_operations(struct pdsfc_dev *pdsfc, dma_addr_t *pa, u32 ep)
{
	struct device *dev = &pdsfc->fwctl.dev;
	struct pds_fwctl_query_data *data;
	dma_addr_t data_pa;
	union pds_core_adminq_cmd cmd = {0};
	union pds_core_adminq_comp comp = {0};
	struct pds_fwctl_query_data_operation *entries = NULL;
	int ret = 0;
	int i;

	/* Query the operations list for the given endpoint */
	data = dma_alloc_coherent(dev->parent, PAGE_SIZE, &data_pa, GFP_KERNEL);
	if (dma_mapping_error(dev->parent, data_pa)) {
		dev_err(dev, "Failed to map operations list\n");
		return ERR_PTR(-ENOMEM);
	}

	cmd.fwctl_query.opcode = PDS_FWCTL_CMD_QUERY;
	cmd.fwctl_query.entity = PDS_FWCTL_RPC_ENDPOINT;
	cmd.fwctl_query.version = 0;
	cmd.fwctl_query.query_data_buf_len = cpu_to_le32(PAGE_SIZE);
	cmd.fwctl_query.query_data_buf_pa = cpu_to_le64(data_pa);
	cmd.fwctl_query.ep = cpu_to_le32(ep);

	ret = pds_client_adminq_cmd(pdsfc->padev, &cmd, sizeof(cmd), &comp, 0);
	if (ret) {
		dev_err(dev, "Failed to send adminq cmd\n");
		dma_free_coherent(dev->parent, PAGE_SIZE, data, data_pa);
		return ERR_PTR(-EIO);
	}

	*pa = data_pa;

	entries = (struct pds_fwctl_query_data_operation *)data->entries;
	dev_dbg(dev, "num_entries %d\n", data->num_entries);
	for (i = 0; i < data->num_entries; i++)
		dev_dbg(dev, "endpoint %d operation: id %x scope %d\n",
			ep, entries[i].id, entries[i].scope);

	return data;
}

static int pdsfc_validate_rpc(struct pdsfc_dev *pdsfc, struct fwctl_rpc_pds *rpc)
{
	struct pds_fwctl_query_data_operation *op_entry = NULL;
	struct pdsfc_rpc_endpoint_info *ep_info = NULL;
	struct device *dev = &pdsfc->fwctl.dev;
	int ret = -EINVAL;
	int i, j;

	if (!pdsfc->ident) {
		dev_err(dev, "Ident not available\n");
		goto done;
	}

	/* validate rpc in_len & out_len based on ident->max_req_sz & max_resp_sz */
	if (rpc->in.len > pdsfc->ident->max_req_sz) {
		dev_err(dev, "Invalid request size %u, max %u\n", rpc->in.len, pdsfc->ident->max_req_sz);
		goto done;
	}

	if (rpc->out.len > pdsfc->ident->max_resp_sz) {
		dev_err(dev, "Invalid response size %u, max %u\n", rpc->out.len, pdsfc->ident->max_resp_sz);
		goto done;
	}

	for (i = 0; i < pdsfc->endpoints->num_entries; i++) {
		ep_info = &pdsfc->endpoint_info[i];
		if (ep_info->endpoint != rpc->in.ep) {
			continue;
		}

		mutex_lock(&ep_info->lock);
		/* query and cache this endpoint's operations */
		if (!ep_info->operations) {
			ep_info->operations = pdsfc_get_operations(pdsfc,
				&ep_info->operations_pa, rpc->in.ep);
			if (!ep_info->operations) {
				mutex_unlock(&ep_info->lock);
				dev_err(dev, "Failed to allocate operations list\n");
				ret = -ENOMEM;
				goto done;
			}
		}
		mutex_unlock(&ep_info->lock);

		op_entry = (struct pds_fwctl_query_data_operation *)ep_info->operations->entries;
		for (j = 0; j < ep_info->operations->num_entries; j++) {
			if (PDS_FWCTL_RPC_OPCODE_CMP(rpc->in.op, op_entry[j].id)) {
				ret = 0;
				break;
			}
		}

		if (j == ep_info->operations->num_entries) {
			dev_err(dev, "Invalid operation %d for endpoint %d\n", rpc->in.op, rpc->in.ep);
			ret = -EINVAL;
			goto done;
		}
		break;
	}

	if (i == pdsfc->endpoints->num_entries) {
		dev_err(dev, "Invalid endpoint %d\n", rpc->in.ep);
		goto done;
	}

done:
	return ret;
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

	ret = pdsfc_validate_rpc(pdsfc, rpc);
	if (ret) {
		dev_err(dev, "Invalid RPC request\n");
		return ERR_PTR(ret);
	}

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
	cmd.fwctl_rpc.flags = PDS_FWCTL_RPC_IND_REQ | PDS_FWCTL_RPC_IND_RESP;
	cmd.fwctl_rpc.ep = cpu_to_le32(rpc->in.ep);
	cmd.fwctl_rpc.op = cpu_to_le32(rpc->in.op);
	cmd.fwctl_rpc.req_pa = cpu_to_le64(in_payload_dma_addr);
	cmd.fwctl_rpc.req_sz = cpu_to_le32(rpc->in.len);
	cmd.fwctl_rpc.resp_pa = cpu_to_le64(out_payload_dma_addr);
	cmd.fwctl_rpc.resp_sz = cpu_to_le32(rpc->out.len);

	dev_dbg(dev, "%s: ep %d op %x"
		" req_pa %llx req_sz %d req_sg %d"
		" resp_pa %llx resp_sz %d resp_sg %d\n",
		__func__, rpc->in.ep, rpc->in.op,
		cmd.fwctl_rpc.req_pa, cmd.fwctl_rpc.req_sz, cmd.fwctl_rpc.req_sg_elems,
		cmd.fwctl_rpc.resp_pa, cmd.fwctl_rpc.resp_sz, cmd.fwctl_rpc.resp_sg_elems);

	dynamic_hex_dump("in ", DUMP_PREFIX_OFFSET, 16, 1, in_payload, rpc->in.len, true);

	ret = pds_client_adminq_cmd(pdsfc->padev, &cmd, sizeof(cmd), &comp, 0);
	if (ret) {
		dev_err(dev, "%s: ep %d op %x"
			" req_pa %llx req_sz %d req_sg %d"
			" resp_pa %llx resp_sz %d resp_sg %d\n",
			__func__, rpc->in.ep, rpc->in.op,
			cmd.fwctl_rpc.req_pa, cmd.fwctl_rpc.req_sz, cmd.fwctl_rpc.req_sg_elems,
			cmd.fwctl_rpc.resp_pa, cmd.fwctl_rpc.resp_sz, cmd.fwctl_rpc.resp_sg_elems);
		out = ERR_PTR(ret);
		goto done;
	}

	dynamic_hex_dump("out ", DUMP_PREFIX_OFFSET, 16, 1, out_payload, rpc->out.len, true);

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
	int ret = 0;

	dev_dbg(dev, "%s\n", __func__);

	padev = container_of(adev, struct pds_auxiliary_dev, aux_dev);
	pdsfc = fwctl_alloc_device(&padev->vf_pdev->dev, &pdsfc_ops, struct pdsfc_dev, fwctl);
	if (!pdsfc) {
		dev_err(dev, "Failed to allocate device, err %d\n", ret);
		return -ENOMEM;
	}
	pdsfc->padev = padev;

	ret = pdsfc_identify(pdsfc);
	if (ret) {
		dev_err(dev, "Failed to identify device, err %d\n", ret);
		return ret;
	}

	ret = pdsfc_init_endpoints(pdsfc);
	if (ret) {
		dev_err(dev, "Failed to init endpoints, err %d\n", ret);
		goto free_ident;
	}

	ret = fwctl_register(&pdsfc->fwctl);
	if (ret) {
		dev_err(dev, "Failed to register device, err %d\n", ret);
		goto free_endpoints;
	}
	auxiliary_set_drvdata(adev, no_free_ptr(pdsfc));

	dev_dbg(dev, "Loaded\n");

	return 0;

free_endpoints:
	pdsfc_free_endpoints(pdsfc);
free_ident:
	pdsfc_free_ident(pdsfc);
	return ret;
}

static void pdsfc_remove(struct auxiliary_device *adev)
{
	struct pdsfc_dev *pdsfc  __free(pdsfc_dev) = auxiliary_get_drvdata(adev);
	struct device *dev = &adev->dev;

	dev_dbg(dev, "%s\n", __func__);

	fwctl_unregister(&pdsfc->fwctl);
	pdsfc_free_operations(pdsfc);
	pdsfc_free_endpoints(pdsfc);
	pdsfc_free_ident(pdsfc);
 
	dev_dbg(dev, "Removed\n");
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
