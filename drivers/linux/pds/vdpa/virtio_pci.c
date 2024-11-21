// SPDX-License-Identifier: GPL-2.0-or-later

/*
 * adapted from drivers/virtio/virtio_pci_modern_dev.c, v6.0-rc1
 */

#include <linux/virtio_pci_modern.h>
#include <linux/pci.h>

#include "virtio_pci.h"

/*
 * pds_vdpa_map_capability - map a part of virtio pci capability
 * @mdev: the modern virtio-pci device
 * @off: offset of the capability
 * @minlen: minimal length of the capability
 * @align: align requirement
 * @start: start from the capability
 * @size: map size
 * @len: the length that is actually mapped
 * @pa: physical address of the capability
 *
 * Returns the io address of for the part of the capability
 */
static void __iomem *
pds_vdpa_map_capability(struct virtio_pci_modern_device *mdev, int off,
			size_t minlen, u32 align, u32 start, u32 size,
			size_t *len, resource_size_t *pa)
{
	struct pci_dev *dev = mdev->pci_dev;
	u8 bar;
	u32 offset, length;
	void __iomem *p;

	pci_read_config_byte(dev, off + offsetof(struct virtio_pci_cap,
						 bar),
			     &bar);
	pci_read_config_dword(dev, off + offsetof(struct virtio_pci_cap, offset),
			      &offset);
	pci_read_config_dword(dev, off + offsetof(struct virtio_pci_cap, length),
			      &length);

	/* Check if the BAR may have changed since we requested the region. */
	if (bar >= PCI_STD_NUM_BARS || !(mdev->modern_bars & (1 << bar))) {
		dev_err(&dev->dev,
			"virtio_pci: bar unexpectedly changed to %u\n", bar);
		return NULL;
	}

	if (length <= start) {
		dev_err(&dev->dev,
			"virtio_pci: bad capability len %u (>%u expected)\n",
			length, start);
		return NULL;
	}

	if (length - start < minlen) {
		dev_err(&dev->dev,
			"virtio_pci: bad capability len %u (>=%zu expected)\n",
			length, minlen);
		return NULL;
	}

	length -= start;

	if (start + offset < offset) {
		dev_err(&dev->dev,
			"virtio_pci: map wrap-around %u+%u\n",
			start, offset);
		return NULL;
	}

	offset += start;

	if (offset & (align - 1)) {
		dev_err(&dev->dev,
			"virtio_pci: offset %u not aligned to %u\n",
			offset, align);
		return NULL;
	}

	if (length > size)
		length = size;

	if (len)
		*len = length;

	if (minlen + offset < minlen ||
	    minlen + offset > pci_resource_len(dev, bar)) {
		dev_err(&dev->dev,
			"virtio_pci: map virtio %zu@%u out of range on bar %i length %lu\n",
			minlen, offset,
			bar, (unsigned long)pci_resource_len(dev, bar));
		return NULL;
	}

	p = pci_iomap_range(dev, bar, offset, length);
	if (!p)
		dev_err(&dev->dev,
			"virtio_pci: unable to map virtio %u@%u on bar %i\n",
			length, offset, bar);
	else if (pa)
		*pa = pci_resource_start(dev, bar) + offset;

	return p;
}

/**
 * virtio_pci_find_capability - walk capabilities to find device info.
 * @dev: the pci device
 * @cfg_type: the VIRTIO_PCI_CAP_* value we seek
 * @ioresource_types: IORESOURCE_MEM and/or IORESOURCE_IO.
 * @bars: the bitmask of BARs
 *
 * Returns offset of the capability, or 0.
 */
static inline int virtio_pci_find_capability(struct pci_dev *dev, u8 cfg_type,
					     u32 ioresource_types, int *bars)
{
	int pos;

	for (pos = pci_find_capability(dev, PCI_CAP_ID_VNDR);
	     pos > 0;
	     pos = pci_find_next_capability(dev, pos, PCI_CAP_ID_VNDR)) {
		u8 type, bar;

		pci_read_config_byte(dev, pos + offsetof(struct virtio_pci_cap,
							 cfg_type),
				     &type);
		pci_read_config_byte(dev, pos + offsetof(struct virtio_pci_cap,
							 bar),
				     &bar);

		/* Ignore structures with reserved BAR values */
		if (bar >= PCI_STD_NUM_BARS)
			continue;

		if (type == cfg_type) {
			if (pci_resource_len(dev, bar) &&
			    pci_resource_flags(dev, bar) & ioresource_types) {
				*bars |= (1 << bar);
				return pos;
			}
		}
	}
	return 0;
}

/*
 * pds_vdpa_probe_virtio: probe the modern virtio pci device, note that the
 * caller is required to enable PCI device before calling this function.
 * @mdev: the modern virtio-pci device
 *
 * Return 0 on succeed otherwise fail
 */
int pds_vdpa_probe_virtio(struct virtio_pci_modern_device *mdev)
{
	struct pci_dev *pci_dev = mdev->pci_dev;
	int err, common, isr, notify, device;
	u32 notify_length;
	u32 notify_offset;

	/* check for a common config: if not, use legacy mode (bar 0). */
	common = virtio_pci_find_capability(pci_dev, VIRTIO_PCI_CAP_COMMON_CFG,
					    IORESOURCE_IO | IORESOURCE_MEM,
					    &mdev->modern_bars);
	if (!common) {
		dev_info(&pci_dev->dev,
			 "virtio_pci: missing common config\n");
		return -ENODEV;
	}

	/* If common is there, these should be too... */
	isr = virtio_pci_find_capability(pci_dev, VIRTIO_PCI_CAP_ISR_CFG,
					 IORESOURCE_IO | IORESOURCE_MEM,
					 &mdev->modern_bars);
	notify = virtio_pci_find_capability(pci_dev, VIRTIO_PCI_CAP_NOTIFY_CFG,
					    IORESOURCE_IO | IORESOURCE_MEM,
					    &mdev->modern_bars);
	if (!isr || !notify) {
		dev_err(&pci_dev->dev,
			"virtio_pci: missing capabilities %i/%i/%i\n",
			common, isr, notify);
		return -EINVAL;
	}

	/* Device capability is only mandatory for devices that have
	 * device-specific configuration.
	 */
	device = virtio_pci_find_capability(pci_dev, VIRTIO_PCI_CAP_DEVICE_CFG,
					    IORESOURCE_IO | IORESOURCE_MEM,
					    &mdev->modern_bars);

	err = pci_request_selected_regions(pci_dev, mdev->modern_bars,
					   "virtio-pci-modern");
	if (err)
		return err;

	err = -EINVAL;
	mdev->common = pds_vdpa_map_capability(mdev, common,
					       sizeof(struct virtio_pci_common_cfg),
					       4, 0,
					       sizeof(struct virtio_pci_common_cfg),
					       NULL, NULL);
	if (!mdev->common)
		goto err_map_common;
	mdev->isr = pds_vdpa_map_capability(mdev, isr, sizeof(u8), 1,
					    0, 1, NULL, NULL);
	if (!mdev->isr)
		goto err_map_isr;

	/* Read notify_off_multiplier from config space. */
	pci_read_config_dword(pci_dev,
			      notify + offsetof(struct virtio_pci_notify_cap,
						notify_off_multiplier),
			      &mdev->notify_offset_multiplier);
	/* Read notify length and offset from config space. */
	pci_read_config_dword(pci_dev,
			      notify + offsetof(struct virtio_pci_notify_cap,
						cap.length),
			      &notify_length);

	pci_read_config_dword(pci_dev,
			      notify + offsetof(struct virtio_pci_notify_cap,
						cap.offset),
			      &notify_offset);

	/* We don't know how many VQs we'll map, ahead of the time.
	 * If notify length is small, map it all now.
	 * Otherwise, map each VQ individually later.
	 */
	if ((u64)notify_length + (notify_offset % PAGE_SIZE) <= PAGE_SIZE) {
		mdev->notify_base = pds_vdpa_map_capability(mdev, notify,
							    2, 2,
							    0, notify_length,
							    &mdev->notify_len,
							    &mdev->notify_pa);
		if (!mdev->notify_base)
			goto err_map_notify;
	} else {
		mdev->notify_map_cap = notify;
	}

	/* Again, we don't know how much we should map, but PAGE_SIZE
	 * is more than enough for all existing devices.
	 */
	if (device) {
		mdev->device = pds_vdpa_map_capability(mdev, device, 0, 4,
						       0, PAGE_SIZE,
						       &mdev->device_len,
						       NULL);
		if (!mdev->device)
			goto err_map_device;
	}

	return 0;

err_map_device:
	if (mdev->notify_base)
		pci_iounmap(pci_dev, mdev->notify_base);
err_map_notify:
	pci_iounmap(pci_dev, mdev->isr);
err_map_isr:
	pci_iounmap(pci_dev, mdev->common);
err_map_common:
	pci_release_selected_regions(pci_dev, mdev->modern_bars);
	return err;
}

void pds_vdpa_remove_virtio(struct virtio_pci_modern_device *mdev)
{
	struct pci_dev *pci_dev = mdev->pci_dev;

	if (mdev->device)
		pci_iounmap(pci_dev, mdev->device);
	if (mdev->notify_base)
		pci_iounmap(pci_dev, mdev->notify_base);
	pci_iounmap(pci_dev, mdev->isr);
	pci_iounmap(pci_dev, mdev->common);
	pci_release_selected_regions(pci_dev, mdev->modern_bars);
}
