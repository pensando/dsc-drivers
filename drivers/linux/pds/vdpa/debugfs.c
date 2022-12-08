// SPDX-License-Identifier: GPL-2.0-only
/* Copyright(c) 2022 Pensando Systems, Inc */

#include <linux/module.h>
#include <linux/pci.h>
#include <linux/types.h>

#include "pds_core_if.h"
#include "pds_vdpa.h"

#include "vdpa_dev.h"
#include "pci_drv.h"
#include "aux_drv.h"
#include "debugfs.h"

#ifdef CONFIG_DEBUG_FS

static struct dentry *dbfs_dir;

#define PRINT_SBIT_NAME(__seq, __f, __name)                     \
	do {                                                    \
		if (__f & __name)                               \
			seq_printf(__seq, " %s", &#__name[16]); \
	} while (0)

static void
print_status_bits(struct seq_file *seq, u16 status)
{
	seq_puts(seq, "status:");
	PRINT_SBIT_NAME(seq, status, VIRTIO_CONFIG_S_ACKNOWLEDGE);
	PRINT_SBIT_NAME(seq, status, VIRTIO_CONFIG_S_DRIVER);
	PRINT_SBIT_NAME(seq, status, VIRTIO_CONFIG_S_DRIVER_OK);
	PRINT_SBIT_NAME(seq, status, VIRTIO_CONFIG_S_FEATURES_OK);
	PRINT_SBIT_NAME(seq, status, VIRTIO_CONFIG_S_NEEDS_RESET);
	PRINT_SBIT_NAME(seq, status, VIRTIO_CONFIG_S_FAILED);
	seq_puts(seq, "\n");
}

#define PRINT_FBIT_NAME(__seq, __f, __name)                \
	do {                                               \
		if (__f & BIT_ULL(__name))                 \
			seq_printf(__seq, " %s", #__name); \
	} while (0)

static void
print_feature_bits(struct seq_file *seq, u64 features)
{
	seq_puts(seq, "features:");
	PRINT_FBIT_NAME(seq, features, VIRTIO_NET_F_CSUM);
	PRINT_FBIT_NAME(seq, features, VIRTIO_NET_F_GUEST_CSUM);
	PRINT_FBIT_NAME(seq, features, VIRTIO_NET_F_CTRL_GUEST_OFFLOADS);
	PRINT_FBIT_NAME(seq, features, VIRTIO_NET_F_MTU);
	PRINT_FBIT_NAME(seq, features, VIRTIO_NET_F_MAC);
	PRINT_FBIT_NAME(seq, features, VIRTIO_NET_F_GUEST_TSO4);
	PRINT_FBIT_NAME(seq, features, VIRTIO_NET_F_GUEST_TSO6);
	PRINT_FBIT_NAME(seq, features, VIRTIO_NET_F_GUEST_ECN);
	PRINT_FBIT_NAME(seq, features, VIRTIO_NET_F_GUEST_UFO);
	PRINT_FBIT_NAME(seq, features, VIRTIO_NET_F_HOST_TSO4);
	PRINT_FBIT_NAME(seq, features, VIRTIO_NET_F_HOST_TSO6);
	PRINT_FBIT_NAME(seq, features, VIRTIO_NET_F_HOST_ECN);
	PRINT_FBIT_NAME(seq, features, VIRTIO_NET_F_HOST_UFO);
	PRINT_FBIT_NAME(seq, features, VIRTIO_NET_F_MRG_RXBUF);
	PRINT_FBIT_NAME(seq, features, VIRTIO_NET_F_STATUS);
	PRINT_FBIT_NAME(seq, features, VIRTIO_NET_F_CTRL_VQ);
	PRINT_FBIT_NAME(seq, features, VIRTIO_NET_F_CTRL_RX);
	PRINT_FBIT_NAME(seq, features, VIRTIO_NET_F_CTRL_VLAN);
	PRINT_FBIT_NAME(seq, features, VIRTIO_NET_F_CTRL_RX_EXTRA);
	PRINT_FBIT_NAME(seq, features, VIRTIO_NET_F_GUEST_ANNOUNCE);
	PRINT_FBIT_NAME(seq, features, VIRTIO_NET_F_MQ);
	PRINT_FBIT_NAME(seq, features, VIRTIO_NET_F_CTRL_MAC_ADDR);
	PRINT_FBIT_NAME(seq, features, VIRTIO_NET_F_HASH_REPORT);
	PRINT_FBIT_NAME(seq, features, VIRTIO_NET_F_RSS);
	PRINT_FBIT_NAME(seq, features, VIRTIO_NET_F_RSC_EXT);
	PRINT_FBIT_NAME(seq, features, VIRTIO_NET_F_STANDBY);
	PRINT_FBIT_NAME(seq, features, VIRTIO_NET_F_SPEED_DUPLEX);
	PRINT_FBIT_NAME(seq, features, VIRTIO_F_NOTIFY_ON_EMPTY);
	PRINT_FBIT_NAME(seq, features, VIRTIO_F_ANY_LAYOUT);
	PRINT_FBIT_NAME(seq, features, VIRTIO_F_VERSION_1);
	PRINT_FBIT_NAME(seq, features, VIRTIO_F_ACCESS_PLATFORM);
	PRINT_FBIT_NAME(seq, features, VIRTIO_F_RING_PACKED);
	PRINT_FBIT_NAME(seq, features, VIRTIO_F_ORDER_PLATFORM);
	PRINT_FBIT_NAME(seq, features, VIRTIO_F_SR_IOV);
	seq_puts(seq, "\n");
}

void
pds_vdpa_debugfs_create(void)
{
	dbfs_dir = debugfs_create_dir(PDS_VDPA_DRV_NAME, NULL);
}

void
pds_vdpa_debugfs_destroy(void)
{
	debugfs_remove_recursive(dbfs_dir);
	dbfs_dir = NULL;
}

void
pds_vdpa_debugfs_add_pcidev(struct pds_vdpa_pci_device *vdpa_pdev)
{
	vdpa_pdev->dentry = debugfs_create_dir(pci_name(vdpa_pdev->pdev), dbfs_dir);
}

void
pds_vdpa_debugfs_del_pcidev(struct pds_vdpa_pci_device *vdpa_pdev)
{
	debugfs_remove_recursive(vdpa_pdev->dentry);
	vdpa_pdev->dentry = NULL;
}

static int
identity_show(struct seq_file *seq, void *v)
{
	struct pds_vdpa_aux *vdpa_aux = seq->private;
	struct vdpa_mgmt_dev *mgmt;

	seq_printf(seq, "aux_dev:            %s\n",
		   dev_name(&vdpa_aux->padev->aux_dev.dev));

	mgmt = &vdpa_aux->vdpa_mdev;
	seq_printf(seq, "max_vqs:            %d\n", mgmt->max_supported_vqs);
	seq_printf(seq, "config_attr_mask:   %#llx\n", mgmt->config_attr_mask);
	seq_printf(seq, "supported_features: %#llx\n", mgmt->supported_features);
	print_feature_bits(seq, mgmt->supported_features);
	seq_printf(seq, "local_mac_bit:      %d\n", vdpa_aux->local_mac_bit);

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(identity);

void
pds_vdpa_debugfs_add_ident(struct pds_vdpa_aux *vdpa_aux)
{
	debugfs_create_file("identity", 0400, vdpa_aux->vdpa_vf->dentry,
			    vdpa_aux, &identity_fops);
}

static int
config_show(struct seq_file *seq, void *v)
{
	struct pds_vdpa_device *pdsv = seq->private;
	struct virtio_net_config *vc = &pdsv->vn_config;

	seq_printf(seq, "mac:                  %pM\n", vc->mac);
	seq_printf(seq, "max_virtqueue_pairs:  %d\n",
		   __virtio16_to_cpu(true, vc->max_virtqueue_pairs));
	seq_printf(seq, "mtu:                  %d\n", __virtio16_to_cpu(true, vc->mtu));
	seq_printf(seq, "speed:                %d\n", le32_to_cpu(vc->speed));
	seq_printf(seq, "duplex:               %d\n", vc->duplex);
	seq_printf(seq, "rss_max_key_size:     %d\n", vc->rss_max_key_size);
	seq_printf(seq, "rss_max_indirection_table_length: %d\n",
		   le16_to_cpu(vc->rss_max_indirection_table_length));
	seq_printf(seq, "supported_hash_types: %#x\n",
		   le32_to_cpu(vc->supported_hash_types));
	seq_printf(seq, "vn_status:            %#x\n",
		   __virtio16_to_cpu(true, vc->status));
	print_status_bits(seq, __virtio16_to_cpu(true, vc->status));

	seq_printf(seq, "hw_status:            %#x\n", pdsv->hw.status);
	print_status_bits(seq, pdsv->hw.status);
	seq_printf(seq, "req_features:         %#llx\n", pdsv->hw.req_features);
	print_feature_bits(seq, pdsv->hw.req_features);
	seq_printf(seq, "actual_features:      %#llx\n", pdsv->hw.actual_features);
	print_feature_bits(seq, pdsv->hw.actual_features);
	seq_printf(seq, "vdpa_index:           %d\n", pdsv->hw.vdpa_index);
	seq_printf(seq, "num_vqs:              %d\n", pdsv->hw.num_vqs);

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(config);

static int
vq_show(struct seq_file *seq, void *v)
{
	struct pds_vdpa_vq_info *vq = seq->private;
	struct pds_vdpa_intr_info *intrs;

	seq_printf(seq, "ready:      %d\n", vq->ready);
	seq_printf(seq, "desc_addr:  %#llx\n", vq->desc_addr);
	seq_printf(seq, "avail_addr: %#llx\n", vq->avail_addr);
	seq_printf(seq, "used_addr:  %#llx\n", vq->used_addr);
	seq_printf(seq, "q_len:      %d\n", vq->q_len);
	seq_printf(seq, "qid:        %d\n", vq->qid);

	seq_printf(seq, "doorbell:   %#llx\n", vq->doorbell);
	seq_printf(seq, "avail_idx:  %d\n", vq->avail_idx);
	seq_printf(seq, "used_idx:   %d\n", vq->used_idx);
	seq_printf(seq, "intr_index: %d\n", vq->intr_index);

	intrs = vq->pdsv->vdpa_aux->vdpa_vf->intrs;
	seq_printf(seq, "irq:        %d\n", intrs[vq->intr_index].irq);
	seq_printf(seq, "irq-name:   %s\n", intrs[vq->intr_index].name);

	seq_printf(seq, "hw_qtype:   %d\n", vq->hw_qtype);
	seq_printf(seq, "hw_qindex:  %d\n", vq->hw_qindex);

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(vq);

void
pds_vdpa_debugfs_add_vdpadev(struct pds_vdpa_device *pdsv)
{
	struct dentry *dentry;
	const char *name;
	int i;

	dentry = pdsv->vdpa_aux->vdpa_vf->dentry;
	name = dev_name(&pdsv->vdpa_dev.dev);

	pdsv->dentry = debugfs_create_dir(name, dentry);

	debugfs_create_file("config", 0400, pdsv->dentry, pdsv, &config_fops);

	for (i = 0; i < pdsv->hw.num_vqs; i++) {
		char name[8];

		snprintf(name, sizeof(name), "vq%02d", i);
		debugfs_create_file(name, 0400, pdsv->dentry, &pdsv->hw.vqs[i], &vq_fops);
	}
}

void
pds_vdpa_debugfs_del_vdpadev(struct pds_vdpa_device *pdsv)
{
	debugfs_remove_recursive(pdsv->dentry);
	pdsv->dentry = NULL;
}

#endif /* CONFIG_DEBUG_FS */
