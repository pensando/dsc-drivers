// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2022 Pensando Systems, Inc */

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/pci.h>

#include "core.h"
#include "pds_adminq.h"
#include "pds_auxbus.h"


/**
 * pds_client_register - Register the client with the device
 * padev:  ptr to the client device info
 * padrv:  ptr to the client driver info
 * Register the client with the core and with the DSC.  The core
 * will fill in the client padev->client_id for use in calls
 * to the DSC AdminQ
 */
static int pds_client_register(struct pds_auxiliary_dev *padev,
			       struct pds_auxiliary_drv *padrv)
{
	union pds_core_adminq_comp comp = { 0 };
	union pds_core_adminq_cmd cmd = { 0 };
	struct device *dev;
	struct pdsc *pdsc;
	int err;
	u16 ci;

	pdsc = (struct pdsc *)dev_get_drvdata(padev->aux_dev.dev.parent);
	dev = pdsc->dev;

	dev_dbg(dev, "%s: %s\n", __func__, dev_name(&padev->aux_dev.dev));

	if (pdsc->state)
		return -ENXIO;

	cmd.client_reg.opcode = PDS_AQ_CMD_CLIENT_REG;
	// TODO: cmd.client_reg.vif_type = xx;
	strscpy(cmd.client_reg.devname, dev_name(&padev->aux_dev.dev),
		sizeof(cmd.client_reg.devname));

	err = pdsc_adminq_post(pdsc, &pdsc->adminqcq[0], &cmd, &comp, false);
	if (err) {
		dev_info(dev, "register dev_name %s with DSC failed, status %d: %pe\n",
			 dev_name(&padev->aux_dev.dev), comp.status, ERR_PTR(err));
		return err;
	}

	ci = le16_to_cpu(comp.client_reg.client_id);
	if (!ci) {
		dev_err(dev, "%s: device returned null client_id\n", __func__);
		return -EIO;
	}

	padev->client_id = ci;
	padev->event_handler = padrv->event_handler;

	return 0;
}

/**
 * pds_client_unregister - Disconnect the client from the device
 * padev:  ptr to the client device info
 * Disconnect the client from the core and with the DSC.
 */
static int pds_client_unregister(struct pds_auxiliary_dev *padev)
{
	union pds_core_adminq_comp comp = { 0 };
	union pds_core_adminq_cmd cmd = { 0 };
	struct device *dev;
	struct pdsc *pdsc;
	int err;
	int i;

	pdsc = (struct pdsc *)dev_get_drvdata(padev->aux_dev.dev.parent);
	dev = pdsc->dev;

	dev_info(dev, "%s: %s client_id %d\n",
		__func__, dev_name(&padev->aux_dev.dev), padev->client_id);

	if (pdsc->state)
		return -ENXIO;

	/* Release client's AdminQ and IRQ resources
	 * The Core will always own index [0], so skip it
	 */
	for (i = 1; i < pdsc->nadminq; i++)
		if (pdsc->adminqcq &&
		    pdsc->adminqcq[i].client_id &&
		    pdsc->adminqcq[i].client_id == padev->client_id)
			pdsc_qcq_free(pdsc, &pdsc->adminqcq[i], true);
	for (i = 1; i < pdsc->nintrs; i++)
		if (pdsc->intr_info &&
		    pdsc->intr_info[i].client_id &&
		    pdsc->intr_info[i].client_id == padev->client_id)
			pdsc_intr_free(pdsc, i);

	cmd.client_unreg.opcode = PDS_AQ_CMD_CLIENT_UNREG;
	cmd.client_unreg.client_id = cpu_to_le16(padev->client_id);

	err = pdsc_adminq_post(pdsc, &pdsc->adminqcq[0], &cmd, &comp, false);
	if (err)
		dev_info(dev, "unregister dev_name %s failed, status %d: %pe\n",
			 dev_name(&padev->aux_dev.dev), comp.status, ERR_PTR(err));

	padev->client_id = 0;

	return err;
}

/**
 * pds_client_adminq_cmd - Process an adminq request for the client
 * padev:  ptr to the client device
 * adminq_id: use 0 for default adminq, or use an adminq_id
 *            returned by new_adminq()
 * req:     ptr to buffer with request
 * req_len: length of actual struct used for request
 * resp:    ptr to buffer where answer is to be copied
 * comp_cb: ptr to callback for signaling async request is
 *          completed.  If NULL, the request is synchronous,
 *          else it will be an asynchronous call.  The callback
 *          function takes an int argument of the completion id
 *          that will be returned by this request. Asynchronous
 *          calls also require the PDS_AQ_FLAG_ASYNC to be set.
 * flags:   optional flags from pds_core_adminq_flags
 *
 * returns 0 on success of a synchronous call (NULL comp_cb),
 *         positive comp_id value for asynchronous call, or
 *         negative for error
 * Client sends pointers to request and response buffers
 * Core copies request data into pds_core_client_request_cmd
 * Core sets other fields as needed
 * Core posts to AdminQ
 * Core copies completion data into response buffer
 * Core either returns (synchronous) or calls comp_cb to
 *   signal asynchronous completion
 */
static int pds_client_adminq_cmd(struct pds_auxiliary_dev *padev,
				 u8 adminq_id,
				 union pds_core_adminq_cmd *req,
				 size_t req_len,
				 union pds_core_adminq_comp *resp,
				 pds_core_cb comp_cb, void *data,
				 u64 flags)
{
	union pds_core_adminq_cmd cmd = { 0 };
	struct pdsc_qcq *qcq;
	struct device *dev;
	struct pdsc *pdsc;
	size_t cp_len;
	bool async;
	int err;

	pdsc = (struct pdsc *)dev_get_drvdata(padev->aux_dev.dev.parent);
	dev = pdsc->dev;

	dev_dbg(dev, "%s: %s adminq %d opcode %d %ssync\n",
		__func__, dev_name(&padev->aux_dev.dev), adminq_id,
		req->opcode, comp_cb ? "a" : "");

	if (pdsc->state)
		return -ENXIO;

	/* Make sure this is a request either on the general Adminq[0] or
	 * on an Adminq that this client owns
	 */
	if (!(adminq_id == 0 ||
	      pdsc->adminqcq[adminq_id].client_id == padev->client_id)) {
		return -EBADF;
	}

	async = !!(flags & PDS_AQ_FLAG_ASYNC);
	if ((comp_cb && !async) || (!comp_cb && async))
		return -EINVAL;

	qcq = &pdsc->adminqcq[adminq_id];

	/* Wrap the client's request */
	cmd.client_request.opcode = PDS_AQ_CMD_CLIENT_CMD;
	cmd.client_request.client_id = cpu_to_le16(padev->client_id);
	cp_len = min_t(size_t, req_len, sizeof(cmd.client_request.client_cmd));
	memcpy(cmd.client_request.client_cmd, req, cp_len);

	if (async)
		err = pdsc_adminq_post_async(pdsc, qcq, &cmd, resp, comp_cb, data);
	else
		err = pdsc_adminq_post(pdsc, qcq, &cmd, resp,
				       !!(flags & PDS_AQ_FLAG_FASTPOLL));
	if (err && err != -EAGAIN)
		dev_info(dev, "client %sadmin cmd failed: %pe\n",
				 comp_cb ? "async " : "", ERR_PTR(err));

	return err;
}

/**
 * pds_client_request_irq - Request an interrupt vector on the core device
 * @padev:     ptr to the client device
 * @name:      ptr to interrupt name string
 * @handler:   ptr to the client handler for interrupt processing
 * @data:      a cookie passed to the handler function
 * @intr_ctrl: ptr to a place to store the DMA of the interrupt control block
 *
 * returns irq index
 */
static int pds_client_request_irq(struct pds_auxiliary_dev *padev,
				  char *name,
				  irq_handler_t handler,
				  void *data,
				  struct pds_core_intr __iomem **intr_ctrl)
{
	struct device *dev;
	struct pdsc *pdsc;
	int index;
	int err;

	pdsc = (struct pdsc *)dev_get_drvdata(padev->aux_dev.dev.parent);
	dev = pdsc->dev;

	dev_dbg(dev, "%s: %s client_id %d\n",
		__func__, dev_name(&padev->aux_dev.dev), padev->client_id);

	if (pdsc->state)
		return -ENXIO;

	mutex_lock(&pdsc->config_lock);

	err = pdsc_intr_alloc(pdsc, name, padev->client_id, handler, data);
	if (err < 0) {
		mutex_unlock(&pdsc->config_lock);
		return err;
	}
	index = err;
	if (intr_ctrl)
		*intr_ctrl = &pdsc->intr_ctrl[index];

	mutex_unlock(&pdsc->config_lock);

	return index;
}

/**
 * pds_client_free_irq - Client frees the interrupt resource
 * padev:   ptr to the client device
 * index:   interrupt index
 */
static int pds_client_free_irq(struct pds_auxiliary_dev *padev,
			       unsigned int index)
{
	struct device *dev;
	struct pdsc *pdsc;

	pdsc = (struct pdsc *)dev_get_drvdata(padev->aux_dev.dev.parent);
	dev = pdsc->dev;

	dev_dbg(dev, "%s: %s client_id %d\n",
		__func__, dev_name(&padev->aux_dev.dev), padev->client_id);

	if (pdsc->state)
		return -ENXIO;

	mutex_lock(&pdsc->config_lock);

	/* Make sure we actually own this irq index */
	if (index >= pdsc->nintrs ||
	    (pdsc->intr_info &&
	     pdsc->intr_info[index].client_id != padev->client_id)) {
		mutex_unlock(&pdsc->config_lock);
		return -EBADF;
	}

	pdsc_intr_free(pdsc, index);

	mutex_unlock(&pdsc->config_lock);

	return 0;
}

/**
 * pds_client_new_adminq - Request a new separate adminq
 * padev:   ptr to the client device
 * length: adminq descriptor length
 * adminq_option_flags: selects RDMA or other AdminQ specific needs
 * name: name for the AdminQ
 * returns an adminq_id to be used in adminq_cmd() requests
 * or negative error code
 */
static int pds_client_new_adminq(struct pds_auxiliary_dev *padev,
				 unsigned int length,
				 u32 adminq_option_flags,
				 const char *name)
{
	struct device *dev;
	const char *qname;
	struct pdsc *pdsc;
	int err = 0;
	int slot;
	int qi;

	pdsc = (struct pdsc *)dev_get_drvdata(padev->aux_dev.dev.parent);
	dev = pdsc->dev;

	qname = name ? name : "cadminq";
	dev_dbg(dev, "%s: %s qname %s flags %#x len %d\n",
		__func__, dev_name(&padev->aux_dev.dev),
		qname, adminq_option_flags, length);

	if (pdsc->state)
		return -ENXIO;

	mutex_lock(&pdsc->config_lock);

	if (!pdsc->adminqcq) {
		err = -ENOMEM;
		goto err_out;
	}

	/* Find an open slot and make sure this requested adminq
	 * doesn't already exist.
	 * We start at 1 to skip over the default adminq.
	 */
	slot = 0;
	for (qi = 1; qi < pdsc->nadminq; qi++) {
		if (!strcmp(qname, pdsc->adminqcq[qi].q.name) &&
		    padev->client_id == pdsc->adminqcq[qi].client_id) {
			err = -EEXIST;
			goto err_out;
		}

		if (!pdsc->adminqcq[qi].q.info && !slot)
			slot = qi;
	}

	if (!slot) {
		err = -ENOSPC;
		goto err_out;
	}

	pdsc->adminqcq[slot].client_id = padev->client_id;
	err = pdsc_qcq_alloc(pdsc, PDS_CORE_QTYPE_ADMINQ, slot,
			     qname,
			     PDS_CORE_QCQ_F_CORE | PDS_CORE_QCQ_F_INTR,
			     length,
			     sizeof(union pds_core_adminq_cmd),
			     sizeof(union pds_core_adminq_comp),
			     0, &pdsc->adminqcq[slot]);

err_out:
	mutex_unlock(&pdsc->config_lock);

	return err ? err : slot;
}

/**
 * pds_client_free_adminq - Free the indicated adminq
 * padev:  ptr to the client device
 * adminq_id: use 0 for default adminq, or use an adminq_id
 *            returned by new_adminq()
 */
static int pds_client_free_adminq(struct pds_auxiliary_dev *padev,
				  uint adminq_id)
{
	struct device *dev;
	struct pdsc *pdsc;

	pdsc = (struct pdsc *)dev_get_drvdata(padev->aux_dev.dev.parent);
	dev = pdsc->dev;

	dev_dbg(dev, "%s: aux_dev.name %s dev_name %s\n",
		__func__, padev->aux_dev.name, dev_name(&padev->aux_dev.dev));

	if (pdsc->state)
		return -ENXIO;

	mutex_lock(&pdsc->config_lock);

	if (adminq_id >= pdsc->nadminq ||
	    (pdsc->adminqcq &&
	     pdsc->adminqcq[adminq_id].client_id != padev->client_id)) {
		mutex_unlock(&pdsc->config_lock);
		return -EBADF;
	}

	pdsc_qcq_free(pdsc, &pdsc->adminqcq[adminq_id], true);

	mutex_unlock(&pdsc->config_lock);

	return 0;
}

/**
 * pds_client_get_fw_state - Get current firmware running/stopped state
 * padev:   ptr to the client device
 * fws:     ptr to state structure
 * returns FW state
 */
static int pds_client_get_fw_state(struct pds_auxiliary_dev *padev,
				   struct pds_fw_state *fws)
{
	struct device *dev;
	struct pdsc *pdsc;

	pdsc = (struct pdsc *)dev_get_drvdata(padev->aux_dev.dev.parent);
	dev = pdsc->dev;

	dev_dbg(dev, "%s: aux_dev.name %s dev_name %s\n",
		__func__, padev->aux_dev.name, dev_name(&padev->aux_dev.dev));

	fws->fw_heartbeat = pdsc->last_hb;
	fws->fw_status = pdsc->fw_status;
	fws->last_fw_time = pdsc->last_fw_time;

	return 0;
}

static struct pds_core_ops pds_core_ops = {
	.register_client = pds_client_register,
	.unregister_client = pds_client_unregister,
	.adminq_cmd = pds_client_adminq_cmd,
	.request_irq = pds_client_request_irq,
	.free_irq = pds_client_free_irq,
	.new_adminq = pds_client_new_adminq,
	.free_adminq = pds_client_free_adminq,
	.fw_state = pds_client_get_fw_state,
};

void pdsc_auxbus_dev_release(struct device *dev)
{
	struct pds_auxiliary_dev *padev =
		container_of(dev, struct pds_auxiliary_dev, aux_dev.dev);

	dev_dbg(dev->parent, "%s: name %s\n", __func__, padev->aux_dev.name);

	devm_kfree(dev->parent, padev);
}

static struct pds_auxiliary_dev *pdsc_auxbus_dev_register(struct pdsc *pdsc,
							  char *name, u32 id,
							  struct pci_dev *client_dev,
							  struct pds_core_ops *ops)
{
	struct pds_auxiliary_dev *padev;
	struct auxiliary_device *aux_dev;
	int err;

	padev = devm_kzalloc(pdsc->dev, sizeof(*padev), GFP_KERNEL);
	if (!padev)
		return NULL;

	padev->ops = ops;
	padev->pcidev = client_dev;

	aux_dev = &padev->aux_dev;
	aux_dev->name = name;
	aux_dev->id = padev->id = id;
	aux_dev->dev.parent = pdsc->dev;
	aux_dev->dev.release = pdsc_auxbus_dev_release;

	err = auxiliary_device_init(aux_dev);
	if (err < 0) {
		dev_warn(pdsc->dev, "auxiliary_device_init of %s id %d failed: %pe\n",
			 name, id, ERR_PTR(err));
		goto err_out;
	}

	err = auxiliary_device_add(aux_dev);
	if (err) {
		auxiliary_device_uninit(aux_dev);
		dev_warn(pdsc->dev, "auxiliary_device_add of %s id %d failed: %pe\n",
			 name, id, ERR_PTR(err));
		goto err_out;
	}

	dev_info(pdsc->dev, "%s: name %s id %d pdsc %p\n",
		 __func__, padev->aux_dev.name, id, pdsc);

	return padev;

err_out:
	devm_kfree(pdsc->dev, padev);
	return NULL;
}

static int pdsc_core_match(struct device *dev, const void *data)
{
	struct pds_auxiliary_dev *curr_padev;
	struct pdsc *curr_pdsc;
	const struct pdsc *pdsc;

	/* Match the core device searching for its clients */
	curr_padev = container_of(dev, struct pds_auxiliary_dev, aux_dev.dev);
	curr_pdsc = (struct pdsc *)dev_get_drvdata(curr_padev->aux_dev.dev.parent);
	pdsc = data;

	if (curr_pdsc == pdsc)
		return 1;

	return 0;
}

int pdsc_auxbus_publish(struct pdsc *pdsc, u16 client_id,
			union pds_core_notifyq_comp *event)
{
	struct pds_auxiliary_dev *padev;
	struct auxiliary_device *aux_dev;

	/* Search aux bus for this core's devices */
	aux_dev = auxiliary_find_device(NULL, pdsc, pdsc_core_match);
	while (aux_dev) {

		padev = container_of(aux_dev, struct pds_auxiliary_dev, aux_dev);

		dev_dbg(pdsc->dev, "%s: found client %s id %d handler %p\n",
			__func__, aux_dev->name,
			padev->client_id, padev->event_handler);

		if ((padev->client_id == client_id ||
		     client_id == PDSC_ALL_CLIENT_IDS) &&
		    padev->event_handler)
			padev->event_handler(padev, event);

		put_device(&aux_dev->dev);

		aux_dev = auxiliary_find_device(&aux_dev->dev,
						pdsc, pdsc_core_match);
	}

	return 0;
}

int pdsc_auxbus_dev_add_pf_device(struct pdsc *pdsc, enum pds_core_vif_types vt)
{
	struct pds_auxiliary_dev *padev;
	int err;

	if (!pdsc->viftype_status[vt].enabled)
		return 0;

	dev_dbg(pdsc->dev, "%s vt %d\n", __func__, vt);

	padev = pdsc_auxbus_dev_register(pdsc,
					 pdsc->viftype_status[vt].name,
					 pdsc->id, pdsc->pdev, &pds_core_ops);
	if (!padev) {
		err = -ENODEV;
		goto err_out;
	}

	pdsc->viftype_status[vt].padev = padev;

	return 0;

err_out:
	return err;

}

int pdsc_auxbus_dev_del_pf_device(struct pdsc *pdsc, enum pds_core_vif_types vt)
{
	struct pds_auxiliary_dev *padev;

	padev = pdsc->viftype_status[vt].padev;
	if (!padev)
		return -ENODEV;

	dev_dbg(pdsc->dev, "%s vt %d\n", __func__, vt);

	pdsc->viftype_status[vt].padev = NULL;

	auxiliary_device_delete(&padev->aux_dev);
	auxiliary_device_uninit(&padev->aux_dev);

	return 0;
}

// TODO: remove this when the real one gets the correct EXPORT_SYMBOL_GPL()
/* Single Root I/O Virtualization */
struct pci_sriov {
	int		pos;		/* Capability position */
	int		nres;		/* Number of resources */
	u32		cap;		/* SR-IOV Capabilities */
	u16		ctrl;		/* SR-IOV Control */
	u16		total_VFs;	/* Total VFs associated with the PF */
	u16		initial_VFs;	/* Initial VFs associated with the PF */
	u16		num_VFs;	/* Number of VFs available */
	u16		offset;		/* First VF Routing ID offset */
	u16		stride;		/* Following VF stride */
	u16		vf_device;	/* VF device ID */
	u32		pgsz;		/* Page size for BAR alignment */
	u8		link;		/* Function Dependency Link */
	u8		max_VF_buses;	/* Max buses consumed by VFs */
	u16		driver_max_VFs;	/* Max num VFs driver supports */
	struct pci_dev	*dev;		/* Lowest numbered PF */
	struct pci_dev	*self;		/* This PF */
	u32		class;		/* VF device */
	u8		hdr_type;	/* VF header type */
	u16		subsystem_vendor; /* VF subsystem vendor */
	u16		subsystem_device; /* VF subsystem device */
	resource_size_t	barsz[PCI_SRIOV_NUM_BARS];	/* VF BAR size */
	bool		drivers_autoprobe; /* Auto probing of VFs by driver */
};
static int my_pci_iov_virtfn_bus(struct pci_dev *dev, int vf_id)
{
	if (!dev->is_physfn)
		return -EINVAL;
	return dev->bus->number + ((dev->devfn + dev->sriov->offset +
				    dev->sriov->stride * vf_id) >> 8);
}

int pdsc_auxbus_dev_add_vf(struct pdsc *pdsc, int vf_id)
{
	struct pds_auxiliary_dev *padev;
	enum pds_core_vif_types vt;
	int err = 0;

	if (!pdsc->vfs)
		return -ENOTTY;

	if (vf_id >= pdsc->num_vfs)
		return -ERANGE;

	if (pdsc->vfs[vf_id].padev) {
		dev_info(pdsc->dev, "%s: vfid %d already running\n", __func__, vf_id);
		return -ENODEV;
	}

	for (vt = 0; vt < PDS_DEV_TYPE_MAX; vt++) {
		u16 vt_support;
		u32 id;

		/* Verify that the type supported and enabled */
		vt_support = !!le16_to_cpu(pdsc->dev_ident.vif_types[vt]);
		if (!(vt_support &&
		      pdsc->viftype_status[vt].max_devs &&
		      pdsc->viftype_status[vt].enabled &&
		      !pdsc->viftype_status[vt].is_pf))
			continue;

		id = PCI_DEVID(my_pci_iov_virtfn_bus(pdsc->pdev, vf_id),
			       pci_iov_virtfn_devfn(pdsc->pdev, vf_id));
		dev_dbg(pdsc->dev, "%s: vfid %d vt %d vtname %s id %#04x (%d) %cenabled\n",
			 __func__, vf_id, vt, pdsc->viftype_status[vt].name,
			 id, id, pdsc->viftype_status[vt].enabled ? '+' : '-');

		padev = pdsc_auxbus_dev_register(pdsc, pdsc->viftype_status[vt].name, id,
						 pdsc->pdev, &pds_core_ops);
		pdsc->vfs[vf_id].padev = padev;

		/* We only support a single type per VF, so jump out here */
		break;
	}

	return err;
}

int pdsc_auxbus_dev_del_vf(struct pdsc *pdsc, int vf_id)
{
	struct pds_auxiliary_dev *padev;

	dev_info(pdsc->dev, "%s: vfid %d\n", __func__, vf_id);

	padev = pdsc->vfs[vf_id].padev;
	pdsc->vfs[vf_id].padev = NULL;
	if (padev) {
		auxiliary_device_delete(&padev->aux_dev);
		auxiliary_device_uninit(&padev->aux_dev);
	}

	return 0;
}
