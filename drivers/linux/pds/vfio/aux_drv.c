// SPDX-License-Identifier: GPL-2.0-only
/* Copyright(c) 2022 Pensando Systems, Inc */

#include <linux/auxiliary_bus.h>
#include <linux/interrupt.h>
#include <linux/io.h>

#include "pds_intr.h"
#include "pds_core_if.h"
#include "pds_adminq.h"
#include "pds_auxbus.h"

#include "aux_drv.h"
#include "vfio_dev.h"
#include "pci_drv.h"
#include "cmds.h"

static const
struct auxiliary_device_id pds_vfio_aux_id_table[] = {
	{ .name = PDS_LM_DEV_NAME, },
	{},
};

static void
pds_vfio_recovery_work(struct work_struct *work)
{
	struct pds_vfio_aux *vfio_aux =
		container_of(work, struct pds_vfio_aux, work);
	struct pds_vfio_pci_device *pds_vfio = vfio_aux->pds_vfio;
	bool deferred_reset_needed = false;

	/* Documentation states that the kernel migration driver must not
	 * generate asynchronous device state transitions outside of
	 * manipulation by the user or the VFIO_DEVICE_RESET ioctl.
	 *
	 * Since recovery is an asynchronous event received from the device,
	 * initiate a deferred reset. Only issue the deferred reset if a
	 * migration is in progress, which will cause the next step of the
	 * migration to fail. Also, if the device is in a state that will
	 * be set to VFIO_DEVICE_STATE_RUNNING on the next action (i.e. VM is
	 * shutdown and device is in VFIO_DEVICE_STATE_STOP) as that will clear
	 * the VFIO_DEVICE_STATE_ERROR when the VM starts back up.
	 */
	mutex_lock(&pds_vfio->state_mutex);
	if ((pds_vfio->state != VFIO_DEVICE_STATE_RUNNING &&
	     pds_vfio->state != VFIO_DEVICE_STATE_ERROR) ||
	    (pds_vfio->state == VFIO_DEVICE_STATE_RUNNING &&
	     pds_vfio_dirty_is_enabled(pds_vfio)))
		deferred_reset_needed = true;
	mutex_unlock(&pds_vfio->state_mutex);

	/* On the next user initiated state transition, the device will
	 * transition to the VFIO_DEVICE_STATE_ERROR. At this point it's the user's
	 * responsibility to reset the device.
	 *
	 * If a VFIO_DEVICE_RESET is requested post recovery and before the next
	 * state transition, then the deferred reset state will be set to
	 * VFIO_DEVICE_STATE_RUNNING.
	 */
	if (deferred_reset_needed)
		pds_vfio_deferred_reset(pds_vfio, VFIO_DEVICE_STATE_ERROR);
}

static void
pds_vfio_aux_notify_handler(struct pds_auxiliary_dev *padev,
			    union pds_core_notifyq_comp *event)
{
	struct device *dev = &padev->aux_dev.dev;
	u16 ecode = le16_to_cpu(event->ecode);

	dev_dbg(dev, "%s: event code %d\n", __func__, ecode);

	/* We don't need to do anything for RESET state==0 as there is no notify
	 * or feedback mechanism available, and it is possible that we won't
	 * even see a state==0 event.
	 *
	 * Any requests from VFIO while state==0 will fail, which will return
	 * error and may cause migration to fail.
	 */
	if (ecode == PDS_EVENT_RESET) {
		dev_info(dev, "%s: PDS_EVENT_RESET event received, state==%d\n",
			 __func__, event->reset.state);
		if (event->reset.state == 1) {
			struct pds_vfio_aux *vfio_aux = auxiliary_get_drvdata(&padev->aux_dev);

			schedule_work(&vfio_aux->work);
		}
	}
}

static int
pds_vfio_aux_probe(struct auxiliary_device *aux_dev,
		   const struct auxiliary_device_id *id)

{
	struct pds_auxiliary_dev *padev =
		container_of(aux_dev, struct pds_auxiliary_dev, aux_dev);
	struct device *dev = &aux_dev->dev;
	struct pds_vfio_aux *vfio_aux;
	struct pci_dev *pdev;
	struct pci_bus *bus;
	int busnr;
	u16 devfn;
	int err;

	vfio_aux = kzalloc(sizeof(*vfio_aux), GFP_KERNEL);
	if (!vfio_aux)
		return -ENOMEM;

	vfio_aux->padev = padev;
	auxiliary_set_drvdata(aux_dev, vfio_aux);

	/* Find our VF PCI device */
	busnr = PCI_BUS_NUM(padev->id);
	devfn = padev->id & 0xff;
	bus = pci_find_bus(0, busnr);
	pdev = pci_get_slot(bus, devfn);

	vfio_aux->pds_vfio = pci_get_drvdata(pdev);
	if (!vfio_aux->pds_vfio) {
		dev_dbg(&pdev->dev, "PCI device not probed yet, defer until PCI device is probed by pds_vfio driver\n");
		err = -EPROBE_DEFER;
		goto err_pci_device_not_probed;
	}

	pdev = vfio_aux->pds_vfio->pdev;
	if (!pds_vfio_is_vfio_pci_driver(pdev)) {
		dev_err(&pdev->dev, "PCI driver is not pds_vfio_pci_driver\n");
		err = -EINVAL;
		goto err_invalid_driver;
	}

	dev_dbg(dev, "%s: id %#04x busnr %#x devfn %#x bus %p pds_vfio %p\n",
		__func__, padev->id, busnr, devfn, bus, vfio_aux->pds_vfio);

	vfio_aux->pds_vfio->coredev = aux_dev->dev.parent;
	vfio_aux->pds_vfio->vfio_aux = vfio_aux;

	vfio_aux->padrv.event_handler = pds_vfio_aux_notify_handler;
	err = pds_vfio_register_client_cmd(vfio_aux->pds_vfio);
	if (err) {
		dev_err(dev, "failed to register as client: %pe\n",
			ERR_PTR(err));
		goto err_register_client;
	}

	INIT_WORK(&vfio_aux->work, pds_vfio_recovery_work);

	return 0;

err_register_client:
	auxiliary_set_drvdata(aux_dev, NULL);
err_invalid_driver:
err_pci_device_not_probed:
	kfree(vfio_aux);
	vfio_aux = NULL;

	return err;
}

static void
pds_vfio_aux_remove(struct auxiliary_device *aux_dev)
{
	struct pds_vfio_aux *vfio_aux = auxiliary_get_drvdata(aux_dev);
	struct pds_vfio_pci_device *pds_vfio = vfio_aux->pds_vfio;

	cancel_work_sync(&vfio_aux->work);

	if (pds_vfio) {
		pds_vfio_dirty_disable(pds_vfio);
		pds_vfio_unregister_client_cmd(pds_vfio);
		vfio_aux->pds_vfio->vfio_aux = NULL;
		pci_dev_put(pds_vfio->pdev);
	}

	kfree(vfio_aux);
	auxiliary_set_drvdata(aux_dev, NULL);
}

static struct auxiliary_driver
pds_vfio_aux_driver = {
	.name = "lm",
	.probe = pds_vfio_aux_probe,
	.remove = pds_vfio_aux_remove,
	.id_table = pds_vfio_aux_id_table,
};

struct auxiliary_driver *
pds_vfio_aux_driver_info(void)
{
	return &pds_vfio_aux_driver;
}

static int
pds_vfio_aux_match_id(struct device *dev, const void *data)
{
	dev_dbg(dev, "%s: %s\n", __func__, (char *)data);
	return !strcmp(dev_name(dev), data);
}

struct pds_vfio_aux *
pds_vfio_aux_get_drvdata(int vf_pci_id)
{
	struct auxiliary_device *aux_dev;
	char name[32];

	snprintf(name, sizeof(name), "%s.%d", PDS_LM_DEV_NAME, vf_pci_id);
	aux_dev = auxiliary_find_device(NULL, name, pds_vfio_aux_match_id);
	if (!aux_dev)
		return NULL;

	return auxiliary_get_drvdata(aux_dev);
}

void
pds_vfio_put_aux_dev(struct pds_vfio_aux *vfio_aux)
{
	put_device(&vfio_aux->padev->aux_dev.dev);
}
