// SPDX-License-Identifier: GPL-2.0-only
/* Copyright(c) 2022 Pensando Systems, Inc */

#include <linux/anon_inodes.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/highmem.h>
#include <linux/vfio.h>
#include <linux/vfio_pci_core.h>
#include <linux/interval_tree.h>

#include "cmds.h"
#include "vfio_dev.h"
#include "trace.h"
#include "dirty.h"

int
pds_vfio_dma_logging_report(struct vfio_device *vdev, unsigned long iova,
			    unsigned long length,
			    struct iova_bitmap *dirty)
{
	struct pds_vfio_pci_device *pds_vfio =
		container_of(vdev, struct pds_vfio_pci_device,
			     vfio_coredev.vdev);

	return pds_vfio_dirty_sync(pds_vfio, dirty, iova, length);
}

int
pds_vfio_dma_logging_start(struct vfio_device *vdev,
			   struct rb_root_cached *ranges, u32 nnodes,
			   u64 *page_size)
{
	struct pds_vfio_pci_device *pds_vfio =
		container_of(vdev, struct pds_vfio_pci_device,
			     vfio_coredev.vdev);
	int err;

	err = pds_vfio_dirty_enable(pds_vfio, ranges, nnodes, page_size);
	if (err)
		return err;

	pds_vfio_send_host_vf_lm_status_cmd(pds_vfio, PDS_LM_STA_IN_PROGRESS);

	return 0;
}

int
pds_vfio_dma_logging_stop(struct vfio_device *vdev)
{
	struct pds_vfio_pci_device *pds_vfio =
		container_of(vdev, struct pds_vfio_pci_device,
			     vfio_coredev.vdev);

	return pds_vfio_dirty_disable(pds_vfio);
}

const char *
pds_vfio_lm_state(enum vfio_device_mig_state state)
{
	switch (state) {
	case VFIO_DEVICE_STATE_ERROR:
		return "VFIO_DEVICE_STATE_ERROR";
	case VFIO_DEVICE_STATE_STOP:
		return "VFIO_DEVICE_STATE_STOP";
	case VFIO_DEVICE_STATE_RUNNING:
		return "VFIO_DEVICE_STATE_RUNNING";
	case VFIO_DEVICE_STATE_STOP_COPY:
		return "VFIO_DEVICE_STATE_STOP_COPY";
	case VFIO_DEVICE_STATE_RESUMING:
		return "VFIO_DEVICE_STATE_RESUMING";
	case VFIO_DEVICE_STATE_RUNNING_P2P:
		return "VFIO_DEVICE_STATE_RUNNING_P2P";
	default:
		return "VFIO_DEVICE_STATE_INVALID";
	}

	return "VFIO_DEVICE_STATE_INVALID";
}

static struct pds_vfio_lm_file *
pds_vfio_get_lm_file(const char *name, const struct file_operations *fops,
		     int flags, u64 size)
{
	struct pds_vfio_lm_file *lm_file = NULL;
	unsigned long long npages;
	struct page **pages;
	unsigned long long i;
	int err = 0;

	if (!size)
		return NULL;

	/* Alloc file structure */
	lm_file = kzalloc(sizeof(*lm_file), GFP_KERNEL);
	if (!lm_file)
		return NULL;

	/* Create file */
	lm_file->filep = anon_inode_getfile(name, fops, lm_file, flags);
	if (!lm_file->filep)
		goto err_get_file;

	stream_open(lm_file->filep->f_inode, lm_file->filep);
	mutex_init(&lm_file->lock);

	lm_file->size = size;

	/* Allocate memory for file pages */
	npages = DIV_ROUND_UP_ULL(lm_file->size, PAGE_SIZE);

	pages = kcalloc(npages, sizeof(*pages), GFP_KERNEL);
	if (!pages)
		goto err_alloc_pages;

	for (i = 0; i < npages; i++) {
		pages[i] = alloc_page(GFP_KERNEL);
		if (!pages[i])
			goto err_alloc_page;
	}

	lm_file->pages = pages;
	lm_file->npages = npages;
	lm_file->alloc_size = npages * PAGE_SIZE;

	/* Create scatterlist of file pages to use for DMA mapping later */
	err = sg_alloc_table_from_pages(&lm_file->sg_table, pages, npages,
					0, size, GFP_KERNEL);
	if (err)
		goto err_alloc_sg_table;

	return lm_file;

err_alloc_sg_table:
err_alloc_page:
	/* free allocated pages */
	for (i = 0; i < npages && pages[i]; i++)
		__free_page(pages[i]);
	kfree(pages);
err_alloc_pages:
	fput(lm_file->filep);
	mutex_destroy(&lm_file->lock);
err_get_file:
	kfree(lm_file);

	return NULL;
}

static void
pds_vfio_put_lm_file(struct pds_vfio_lm_file *lm_file)
{
	unsigned long long i;

	mutex_lock(&lm_file->lock);

	lm_file->size = 0;
	lm_file->alloc_size = 0;

	/* Free scatter list of file pages*/
	sg_free_table(&lm_file->sg_table);

	/* Free allocated file pages */
	for (i = 0; i < lm_file->npages && lm_file->pages[i]; i++)
		__free_page(lm_file->pages[i]);
	kfree(lm_file->pages);
	lm_file->pages = NULL;

	/* Delete file */
	fput(lm_file->filep);
	lm_file->filep = NULL;

	mutex_unlock(&lm_file->lock);

	mutex_destroy(&lm_file->lock);

	/* Free file structure */
	kfree(lm_file);
}

void
pds_vfio_put_save_file(struct pds_vfio_pci_device *pds_vfio)
{
	if (!pds_vfio->save_file)
		return;

	pds_vfio_put_lm_file(pds_vfio->save_file);
	pds_vfio->save_file = NULL;
}

void
pds_vfio_put_restore_file(struct pds_vfio_pci_device *pds_vfio)
{
	if (!pds_vfio->restore_file)
		return;

	pds_vfio_put_lm_file(pds_vfio->restore_file);
	pds_vfio->restore_file = NULL;
}

static struct page *
pds_vfio_get_file_page(struct pds_vfio_lm_file *lm_file,
		       unsigned long offset)
{
	unsigned long cur_offset = 0;
	struct scatterlist *sg;
	unsigned int i;

	/* All accesses are sequential */
	if (offset < lm_file->last_offset || !lm_file->last_offset_sg) {
		lm_file->last_offset = 0;
		lm_file->last_offset_sg = lm_file->sg_table.sgl;
		lm_file->sg_last_entry = 0;
	}

	cur_offset = lm_file->last_offset;

	for_each_sg(lm_file->last_offset_sg, sg,
		    lm_file->sg_table.orig_nents - lm_file->sg_last_entry,
		    i) {
		if (offset < sg->length + cur_offset) {
			lm_file->last_offset_sg = sg;
			lm_file->sg_last_entry += i;
			lm_file->last_offset = cur_offset;
			return nth_page(sg_page(sg),
					(offset - cur_offset) / PAGE_SIZE);
		}
		cur_offset += sg->length;
	}

	return NULL;
}

static int
pds_vfio_release_file(struct inode *inode, struct file *filp)
{
	struct pds_vfio_lm_file *lm_file = filp->private_data;

	// TODO: May be we should only cleanup from live migration FSM
	// pds_vfio_put_lm_file(lm_file);
	lm_file->size = 0;

	return 0;
}

static ssize_t
pds_vfio_save_read(struct file *filp, char __user *buf, size_t len, loff_t *pos)
{
	struct pds_vfio_lm_file *lm_file = filp->private_data;
	ssize_t done = 0;

	if (pos)
		return -ESPIPE;
	pos = &filp->f_pos;

	mutex_lock(&lm_file->lock);
	if (*pos > lm_file->size) {
		done = -EINVAL;
		goto out_unlock;
	}

	len = min_t(size_t, lm_file->size - *pos, len);
	while (len) {
		size_t page_offset;
		struct page *page;
		size_t page_len;
		u8 *from_buff;
		int err;

		page_offset = (*pos) % PAGE_SIZE;
		page = pds_vfio_get_file_page(lm_file, *pos - page_offset);
		if (!page) {
			if (done == 0)
				done = -EINVAL;
			goto out_unlock;
		}

		page_len = min_t(size_t, len, PAGE_SIZE - page_offset);
		from_buff = kmap_local_page(page);
		err = copy_to_user(buf, from_buff + page_offset, page_len);
		kunmap_local(from_buff);
		if (err) {
			done = -EFAULT;
			goto out_unlock;
		}
		*pos += page_len;
		len -= page_len;
		done += page_len;
		buf += page_len;
	}

out_unlock:
	mutex_unlock(&lm_file->lock);
	return done;
}

static const struct file_operations
pds_vfio_save_fops = {
	.owner = THIS_MODULE,
	.read = pds_vfio_save_read,
	.release = pds_vfio_release_file,
	.llseek = no_llseek,
};

static int
pds_vfio_get_save_file(struct pds_vfio_pci_device *pds_vfio)
{
	struct pds_vfio_lm_file *lm_file;
	struct pci_dev *pdev = pds_vfio->pdev;
	int err = 0;
	u64 size;

	/* Get live migration state size in this state */
	err = pds_vfio_get_lm_status_cmd(pds_vfio, &size);
	if (err) {
		dev_err(&pdev->dev, "failed to get save status: %pe\n",
			ERR_PTR(err));
		goto err_get_lm_status;
	}

	dev_dbg(&pdev->dev, "save status, size = %lld\n", size);

	if (!size) {
		err = -EIO;
		dev_err(&pdev->dev, "invalid state size\n");
		goto err_get_lm_status;
	}

	lm_file = pds_vfio_get_lm_file("pds_vfio_lm", &pds_vfio_save_fops,
				       O_RDONLY, size);
	if (!lm_file) {
		err = -ENOENT;
		dev_err(&pdev->dev, "failed to create save file\n");
		goto err_get_lm_file;
	}

	dev_dbg(&pdev->dev, "size = %lld, alloc_size = %lld, npages = %lld\n",
		lm_file->size, lm_file->alloc_size, lm_file->npages);

	pds_vfio->save_file = lm_file;

	return 0;

err_get_lm_file:
err_get_lm_status:
	return err;
}

static ssize_t
pds_vfio_restore_write(struct file *filp, const char __user *buf, size_t len, loff_t *pos)
{
	struct pds_vfio_lm_file *lm_file = filp->private_data;
	loff_t requested_length;
	ssize_t done = 0;

	if (pos)
		return -ESPIPE;

	pos = &filp->f_pos;

	if (*pos < 0 ||
	    check_add_overflow((loff_t)len, *pos, &requested_length))
		return -EINVAL;

	mutex_lock(&lm_file->lock);

	while (len) {
		size_t page_offset;
		struct page *page;
		size_t page_len;
		u8 *to_buff;
		int err;

		page_offset = (*pos) % PAGE_SIZE;
		page = pds_vfio_get_file_page(lm_file, *pos - page_offset);
		if (!page) {
			if (done == 0)
				done = -EINVAL;
			goto out_unlock;
		}

		page_len = min_t(size_t, len, PAGE_SIZE - page_offset);
		to_buff = kmap_local_page(page);
		err = copy_from_user(to_buff + page_offset, buf, page_len);
		kunmap_local(to_buff);
		if (err) {
			done = -EFAULT;
			goto out_unlock;
		}
		*pos += page_len;
		len -= page_len;
		done += page_len;
		buf += page_len;
		lm_file->size += page_len;
	}
out_unlock:
	mutex_unlock(&lm_file->lock);
	return done;
}

static const struct file_operations
pds_vfio_restore_fops = {
	.owner = THIS_MODULE,
	.write = pds_vfio_restore_write,
	.release = pds_vfio_release_file,
	.llseek = no_llseek,
};

static int
pds_vfio_get_restore_file(struct pds_vfio_pci_device *pds_vfio)
{
	struct pds_vfio_lm_file *lm_file;
	struct pci_dev *pdev = pds_vfio->pdev;
	int err = 0;
	u64 size;

	size = sizeof(union pds_lm_dev_state);

	dev_dbg(&pdev->dev, "restore status, size = %lld\n", size);

	if (!size) {
		err = -EIO;
		dev_err(&pdev->dev, "invalid state size");
		goto err_get_lm_status;
	}

	lm_file = pds_vfio_get_lm_file("pds_vfio_lm", &pds_vfio_restore_fops,
				       O_WRONLY, size);
	if (!lm_file) {
		err = -ENOENT;
		dev_err(&pdev->dev, "failed to create restore file");
		goto err_get_lm_file;
	}
	pds_vfio->restore_file = lm_file;

	return 0;

err_get_lm_file:
err_get_lm_status:
	return err;
}

struct file *
pds_vfio_step_device_state_locked(struct pds_vfio_pci_device *pds_vfio,
				  enum vfio_device_mig_state next)
{
	enum vfio_device_mig_state cur = pds_vfio->state;
	struct device *dev = &pds_vfio->pdev->dev;
	unsigned long lm_action_start;
	int err = 0;

	dev_info(dev, "%s => %s\n",
		 pds_vfio_lm_state(cur), pds_vfio_lm_state(next));

	lm_action_start = jiffies;
	if (cur == VFIO_DEVICE_STATE_STOP && next == VFIO_DEVICE_STATE_STOP_COPY) {
		/* Device is already stopped
		 * create save device data file & get device state from firmware
		 */
		err = pds_vfio_get_save_file(pds_vfio);
		if (err)
			return ERR_PTR(err);

		/* Get device state */
		err = pds_vfio_get_lm_state_cmd(pds_vfio);
		if (err) {
			pds_vfio_put_save_file(pds_vfio);
			return ERR_PTR(err);
		}

		trace_lm_action_time(dev, "SAVE", jiffies - lm_action_start);

		return pds_vfio->save_file->filep;
	}

	if (cur == VFIO_DEVICE_STATE_STOP_COPY && next == VFIO_DEVICE_STATE_STOP) {
		/* Device is already stopped
		 * delete the save device state file
		 */
		pds_vfio_put_save_file(pds_vfio);
		pds_vfio_send_host_vf_lm_status_cmd(pds_vfio,
						    PDS_LM_STA_NONE);
		/* TODO: Remove this if/when QEMU correctly disables dirty
		 * tracking once the source device has reached this stage (i.e.
		 * migration is done and dirty tracking is not needed anymore).
		 */
		pds_vfio_dirty_disable(pds_vfio);
		return NULL;
	}

	if (cur == VFIO_DEVICE_STATE_STOP && next == VFIO_DEVICE_STATE_RESUMING) {
		/* create resume device data file */
		err = pds_vfio_get_restore_file(pds_vfio);
		if (err)
			return ERR_PTR(err);

		return pds_vfio->restore_file->filep;
	}

	if (cur == VFIO_DEVICE_STATE_RESUMING && next == VFIO_DEVICE_STATE_STOP) {
		/* Set device state */
		err = pds_vfio_set_lm_state_cmd(pds_vfio);
		if (err)
			return ERR_PTR(err);

		trace_lm_action_time(dev, "RESTORE", jiffies - lm_action_start);

		/* delete resume device data file */
		pds_vfio_put_restore_file(pds_vfio);
		return NULL;
	}

	if (cur == VFIO_DEVICE_STATE_RUNNING && next == VFIO_DEVICE_STATE_STOP) {
		/* Device should be stopped
		 * no interrupts, dma or change in internal state
		 */
		err = pds_vfio_suspend_device_cmd(pds_vfio);
		if (err)
			return ERR_PTR(err);

		trace_lm_action_time(dev, "SUSPEND", jiffies - lm_action_start);

		return NULL;
	}

	if (cur == VFIO_DEVICE_STATE_STOP && next == VFIO_DEVICE_STATE_RUNNING) {
		/* Device should be functional
		 * interrupts, dma, mmio or changes to internal state is allowed
		 */
		err = pds_vfio_resume_device_cmd(pds_vfio);
		if (err)
			return ERR_PTR(err);

		trace_lm_action_time(dev, "RESUME", jiffies - lm_action_start);

		pds_vfio_send_host_vf_lm_status_cmd(pds_vfio,
						    PDS_LM_STA_NONE);
		return NULL;
	}

	return ERR_PTR(-EINVAL);
}
