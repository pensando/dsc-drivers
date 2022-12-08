// SPDX-License-Identifier: GPL-2.0-only
/* Copyright(c) 2022 Pensando Systems, Inc */

#include <linux/vfio.h>
#include <linux/vfio_pci_core.h>

#include "lm.h"
#include "vfio_dev.h"
#include "aux_drv.h"

struct pds_vfio_pci_device *
pds_vfio_pci_drvdata(struct pci_dev *pdev)
{
	struct vfio_pci_core_device *core_device = dev_get_drvdata(&pdev->dev);

	return container_of(core_device, struct pds_vfio_pci_device,
			    vfio_coredev);
}

void
pds_vfio_state_mutex_unlock(struct pds_vfio_pci_device *pds_vfio)
{
again:
	spin_lock(&pds_vfio->reset_lock);
	if (pds_vfio->deferred_reset) {
		pds_vfio->deferred_reset = false;
		if (pds_vfio->state == VFIO_DEVICE_STATE_ERROR) {
			dev_dbg(&pds_vfio->pdev->dev, "Transitioning from VFIO_DEVICE_STATE_ERROR to %s\n",
				pds_vfio_lm_state(pds_vfio->deferred_reset_state));
			pds_vfio->state = pds_vfio->deferred_reset_state;
			pds_vfio_put_restore_file(pds_vfio);
			pds_vfio_put_save_file(pds_vfio);
		} else if (pds_vfio->deferred_reset_state == VFIO_DEVICE_STATE_ERROR) {
			dev_dbg(&pds_vfio->pdev->dev, "Transitioning from %s to VFIO_DEVICE_STATE_ERROR based on deferred_reset request\n",
				pds_vfio_lm_state(pds_vfio->state));
			pds_vfio->state = VFIO_DEVICE_STATE_ERROR;
		}
		pds_vfio->deferred_reset_state = VFIO_DEVICE_STATE_RUNNING;
		spin_unlock(&pds_vfio->reset_lock);
		goto again;
	}
	mutex_unlock(&pds_vfio->state_mutex);
	spin_unlock(&pds_vfio->reset_lock);
}

void
pds_vfio_reset(struct pds_vfio_pci_device *pds_vfio)
{
	spin_lock(&pds_vfio->reset_lock);
	pds_vfio->deferred_reset = true;
	pds_vfio->deferred_reset_state = VFIO_DEVICE_STATE_RUNNING;
	if (!mutex_trylock(&pds_vfio->state_mutex)) {
		spin_unlock(&pds_vfio->reset_lock);
		return;
	}
	spin_unlock(&pds_vfio->reset_lock);
	pds_vfio_state_mutex_unlock(pds_vfio);
}

void
pds_vfio_deferred_reset(struct pds_vfio_pci_device *pds_vfio,
			enum vfio_device_mig_state reset_state)
{
	dev_info(&pds_vfio->pdev->dev, "Requesting deferred_reset to state %s\n",
		 pds_vfio_lm_state(reset_state));
	spin_lock(&pds_vfio->reset_lock);
	pds_vfio->deferred_reset = true;
	pds_vfio->deferred_reset_state = reset_state;
	spin_unlock(&pds_vfio->reset_lock);
}

struct file *
pds_vfio_set_device_state(struct vfio_device *vdev,
			  enum vfio_device_mig_state new_state)
{
	struct pds_vfio_pci_device *pds_vfio =
		container_of(vdev, struct pds_vfio_pci_device,
			     vfio_coredev.vdev);
	struct file *res = NULL;

	if (!pds_vfio->vfio_aux)
		return ERR_PTR(-ENODEV);

	mutex_lock(&pds_vfio->state_mutex);
	/* only way to transition out of VFIO_DEVICE_STATE_ERROR is via
	 * VFIO_DEVICE_RESET, so prevent the state machine from running since
	 * vfio_mig_get_next_state() will throw a WARN_ON() when transitioning
	 * from VFIO_DEVICE_STATE_ERROR to any other state
	 */
	while (pds_vfio->state != VFIO_DEVICE_STATE_ERROR &&
	       new_state != pds_vfio->state) {
		enum vfio_device_mig_state next_state;

		int err = vfio_mig_get_next_state(vdev, pds_vfio->state,
						  new_state, &next_state);
		if (err) {
			res = ERR_PTR(err);
			break;
		}

		res = pds_vfio_step_device_state_locked(pds_vfio, next_state);
		if (IS_ERR(res))
			break;

		pds_vfio->state = next_state;

		if (WARN_ON(res && new_state != pds_vfio->state)) {
			res = ERR_PTR(-EINVAL);
			break;
		}
	}
	pds_vfio_state_mutex_unlock(pds_vfio);
	/* still waiting on a deferred_reset */
	if (pds_vfio->state == VFIO_DEVICE_STATE_ERROR)
		res = ERR_PTR(-EIO);

	return res;
}

int
pds_vfio_get_device_state(struct vfio_device *vdev,
			  enum vfio_device_mig_state *current_state)
{
	struct pds_vfio_pci_device *pds_vfio =
		container_of(vdev, struct pds_vfio_pci_device,
			     vfio_coredev.vdev);

	mutex_lock(&pds_vfio->state_mutex);
	*current_state = pds_vfio->state;
	pds_vfio_state_mutex_unlock(pds_vfio);
	return 0;
}

static const struct vfio_migration_ops
pds_vfio_lm_ops = {
	.migration_set_state = pds_vfio_set_device_state,
	.migration_get_state = pds_vfio_get_device_state
};

static const struct vfio_log_ops
pds_vfio_log_ops = {
	.log_start = pds_vfio_dma_logging_start,
	.log_stop = pds_vfio_dma_logging_stop,
	.log_read_and_clear = pds_vfio_dma_logging_report,
};

static int
pds_vfio_init_device(struct vfio_device *vdev)
{
	struct pds_vfio_pci_device *pds_vfio =
		container_of(vdev, struct pds_vfio_pci_device,
			     vfio_coredev.vdev);
	struct pci_dev *pdev = to_pci_dev(vdev->dev);
	struct pds_vfio_aux *vfio_aux;
	int err;

	err = vfio_pci_core_init_dev(vdev);
	if (err)
		return err;

	pds_vfio->vf_id = pci_iov_vf_id(pdev);
	pds_vfio->pci_id = PCI_DEVID(pdev->bus->number, pdev->devfn);
	vfio_aux = pds_vfio_aux_get_drvdata(pds_vfio->pci_id);
	if (vfio_aux) {
		vfio_aux->pds_vfio = pds_vfio;
		pds_vfio->coredev = vfio_aux->padev->aux_dev.dev.parent;
		pds_vfio->vfio_aux = vfio_aux;
		pds_vfio_put_aux_dev(vfio_aux);
	}

	vdev->migration_flags = VFIO_MIGRATION_STOP_COPY;
	vdev->mig_ops = &pds_vfio_lm_ops;
	vdev->log_ops = &pds_vfio_log_ops;

	dev_dbg(&pdev->dev, "%s: PF %#04x VF %#04x (%d) vf_id %d domain %d vfio_aux %p pds_vfio %p\n",
		__func__, pci_dev_id(pdev->physfn),
		pds_vfio->pci_id, pds_vfio->pci_id, pds_vfio->vf_id,
		pci_domain_nr(pdev->bus), pds_vfio->vfio_aux, pds_vfio);

	return 0;
}

static int
pds_vfio_open_device(struct vfio_device *vdev)
{
	struct pds_vfio_pci_device *pds_vfio =
		container_of(vdev, struct pds_vfio_pci_device,
			     vfio_coredev.vdev);
	int err;

	err = vfio_pci_core_enable(&pds_vfio->vfio_coredev);
	if (err)
		return err;

	mutex_init(&pds_vfio->state_mutex);
	dev_dbg(&pds_vfio->pdev->dev, "%s: %s => VFIO_DEVICE_STATE_RUNNING\n",
		__func__, pds_vfio_lm_state(pds_vfio->state));
	pds_vfio->state = VFIO_DEVICE_STATE_RUNNING;
	pds_vfio->deferred_reset_state = VFIO_DEVICE_STATE_RUNNING;

	vfio_pci_core_finish_enable(&pds_vfio->vfio_coredev);

	return 0;
}

static void
pds_vfio_close_device(struct vfio_device *vdev)
{
	struct pds_vfio_pci_device *pds_vfio =
		container_of(vdev, struct pds_vfio_pci_device,
			     vfio_coredev.vdev);

	mutex_destroy(&pds_vfio->state_mutex);
	vfio_pci_core_close_device(vdev);
}

static const struct vfio_device_ops
pds_vfio_ops = {
	.name = "pds-vfio",
	.init = pds_vfio_init_device,
	.release = vfio_pci_core_release_dev,
	.open_device = pds_vfio_open_device,
	.close_device = pds_vfio_close_device,
	.ioctl = vfio_pci_core_ioctl,
	.device_feature = vfio_pci_core_ioctl_feature,
	.read = vfio_pci_core_read,
	.write = vfio_pci_core_write,
	.mmap = vfio_pci_core_mmap,
	.request = vfio_pci_core_request,
	.match = vfio_pci_core_match,
};

const struct vfio_device_ops *
pds_vfio_ops_info(void)
{
	return &pds_vfio_ops;
}
