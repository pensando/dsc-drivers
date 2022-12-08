// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2022 Pensando Systems, Inc */

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/pci.h>
#include <linux/delay.h>
#include <net/devlink.h>
#include <linux/etherdevice.h>

#include "core.h"

static const char *pdsc_vf_attr_to_str(enum pds_core_vf_attr attr)
{
	switch (attr) {
	case PDS_CORE_VF_ATTR_SPOOFCHK:
		return "PDS_CORE_VF_ATTR_SPOOFCHK";
	case PDS_CORE_VF_ATTR_TRUST:
		return "PDS_CORE_VF_ATTR_TRUST";
	case PDS_CORE_VF_ATTR_LINKSTATE:
		return "PDS_CORE_VF_ATTR_LINKSTATE";
	case PDS_CORE_VF_ATTR_MAC:
		return "PDS_CORE_VF_ATTR_MAC";
	case PDS_CORE_VF_ATTR_VLAN:
		return "PDS_CORE_VF_ATTR_VLAN";
	case PDS_CORE_VF_ATTR_RATE:
		return "PDS_CORE_VF_ATTR_RATE";
	case PDS_CORE_VF_ATTR_STATSADDR:
		return "PDS_CORE_VF_ATTR_STATSADDR";
	default:
		return "PDS_CORE_VF_ATTR_UNKNOWN";
	}
}

static int pdsc_get_vf_stats(struct net_device *netdev, int vf,
			     struct ifla_vf_stats *vf_stats)
{
	struct pdsc *pdsc = *(struct pdsc **)netdev_priv(netdev);
	struct pds_core_vf_stats *vs;
	int ret = 0;

	if (!netif_device_present(netdev))
		return -EBUSY;

	down_read(&pdsc->vf_op_lock);

	if (vf >= pci_num_vf(pdsc->pdev) || !pdsc->vfs) {
		ret = -EINVAL;
	} else {
		memset(vf_stats, 0, sizeof(*vf_stats));
		vs = &pdsc->vfs[vf].stats;

		vf_stats->rx_packets = le64_to_cpu(vs->rx_ucast_packets);
		vf_stats->tx_packets = le64_to_cpu(vs->tx_ucast_packets);
		vf_stats->rx_bytes   = le64_to_cpu(vs->rx_ucast_bytes);
		vf_stats->tx_bytes   = le64_to_cpu(vs->tx_ucast_bytes);
		vf_stats->broadcast  = le64_to_cpu(vs->rx_bcast_packets);
		vf_stats->multicast  = le64_to_cpu(vs->rx_mcast_packets);
		vf_stats->rx_dropped = le64_to_cpu(vs->rx_ucast_drop_packets) +
				       le64_to_cpu(vs->rx_mcast_drop_packets) +
				       le64_to_cpu(vs->rx_bcast_drop_packets);
		vf_stats->tx_dropped = le64_to_cpu(vs->tx_ucast_drop_packets) +
				       le64_to_cpu(vs->tx_mcast_drop_packets) +
				       le64_to_cpu(vs->tx_bcast_drop_packets);
	}

	up_read(&pdsc->vf_op_lock);
	return ret;
}

static int pdsc_get_fw_vf_config(struct pdsc *pdsc, int vf, struct pdsc_vf *vfdata)
{
	struct pds_core_vf_getattr_comp comp = { 0 };
	int err;
	u8 attr;

	attr = PDS_CORE_VF_ATTR_VLAN;
	err = pdsc_dev_cmd_vf_getattr(pdsc, vf, attr, &comp);
	if (err && comp.status != PDS_RC_ENOSUPP)
		goto err_out;
	if (!err)
		vfdata->vlanid = comp.vlanid;

	attr = PDS_CORE_VF_ATTR_SPOOFCHK;
	err = pdsc_dev_cmd_vf_getattr(pdsc, vf, attr, &comp);
	if (err && comp.status != PDS_RC_ENOSUPP)
		goto err_out;
	if (!err)
		vfdata->spoofchk = comp.spoofchk;

	attr = PDS_CORE_VF_ATTR_LINKSTATE;
	err = pdsc_dev_cmd_vf_getattr(pdsc, vf, attr, &comp);
	if (err && comp.status != PDS_RC_ENOSUPP)
		goto err_out;
	if (!err) {
		switch (comp.linkstate) {
		case PDS_CORE_VF_LINK_STATUS_UP:
			vfdata->linkstate = IFLA_VF_LINK_STATE_ENABLE;
			break;
		case PDS_CORE_VF_LINK_STATUS_DOWN:
			vfdata->linkstate = IFLA_VF_LINK_STATE_DISABLE;
			break;
		case PDS_CORE_VF_LINK_STATUS_AUTO:
			vfdata->linkstate = IFLA_VF_LINK_STATE_AUTO;
			break;
		default:
			dev_warn(pdsc->dev, "Unexpected link state %u\n", comp.linkstate);
			break;
		}
	}

	attr = PDS_CORE_VF_ATTR_RATE;
	err = pdsc_dev_cmd_vf_getattr(pdsc, vf, attr, &comp);
	if (err && comp.status != PDS_RC_ENOSUPP)
		goto err_out;
	if (!err)
		vfdata->maxrate = comp.maxrate;

	attr = PDS_CORE_VF_ATTR_TRUST;
	err = pdsc_dev_cmd_vf_getattr(pdsc, vf, attr, &comp);
	if (err && comp.status != PDS_RC_ENOSUPP)
		goto err_out;
	if (!err)
		vfdata->trusted = comp.trust;

	attr = PDS_CORE_VF_ATTR_MAC;
	err = pdsc_dev_cmd_vf_getattr(pdsc, vf, attr, &comp);
	if (err && comp.status != PDS_RC_ENOSUPP)
		goto err_out;
	if (!err)
		ether_addr_copy(vfdata->macaddr, comp.macaddr);

err_out:
	if (err)
		dev_err(pdsc->dev, "Failed to get %s for VF %d\n",
			pdsc_vf_attr_to_str(attr), vf);

	return err;
}

static int pdsc_get_vf_config(struct net_device *netdev,
			      int vf, struct ifla_vf_info *ivf)
{
	struct pdsc *pdsc = *(struct pdsc **)netdev_priv(netdev);
	struct pdsc_vf vfdata = { 0 };
	int ret = 0;

	if (!netif_device_present(netdev))
		return -EBUSY;

	down_read(&pdsc->vf_op_lock);

	if (vf >= pci_num_vf(pdsc->pdev) || !pdsc->vfs) {
		ret = -EINVAL;
	} else {
		ivf->vf = vf;
		ivf->qos = 0;

		ret = pdsc_get_fw_vf_config(pdsc, vf, &vfdata);
		if (!ret) {
			ivf->vlan         = le16_to_cpu(vfdata.vlanid);
			ivf->spoofchk     = vfdata.spoofchk;
			ivf->linkstate    = vfdata.linkstate;
			ivf->max_tx_rate  = le32_to_cpu(vfdata.maxrate);
			ivf->trusted      = vfdata.trusted;
			ether_addr_copy(ivf->mac, vfdata.macaddr);
		}
	}

	up_read(&pdsc->vf_op_lock);
	return ret;
}

int pdsc_set_vf_config(struct pdsc *pdsc, int vf,
			struct pds_core_vf_setattr_cmd *vfc)
{
	union pds_core_dev_comp comp = { 0 };
	union pds_core_dev_cmd cmd = {
		.vf_setattr.opcode = PDS_CORE_CMD_VF_SETATTR,
		.vf_setattr.attr = vfc->attr,
		.vf_setattr.vf_index = cpu_to_le16(vf),
	};
	int err;

	if (vf >= pdsc->num_vfs)
		return -EINVAL;

	memcpy(cmd.vf_setattr.pad, vfc->pad, sizeof(vfc->pad));

	err = pdsc_devcmd(pdsc, &cmd, &comp, pdsc->devcmd_timeout);

	return err;
}

static int pdsc_set_vf_mac(struct net_device *netdev, int vf, u8 *mac)
{
	struct pds_core_vf_setattr_cmd vfc = { .attr = PDS_CORE_VF_ATTR_MAC };
	struct pdsc *pdsc = *(struct pdsc **)netdev_priv(netdev);
	int ret;

	if (!(is_zero_ether_addr(mac) || is_valid_ether_addr(mac)))
		return -EINVAL;

	if (!netif_device_present(netdev))
		return -EBUSY;

	down_write(&pdsc->vf_op_lock);

	if (vf >= pci_num_vf(pdsc->pdev) || !pdsc->vfs) {
		ret = -EINVAL;
	} else {
		ether_addr_copy(vfc.macaddr, mac);
		dev_dbg(pdsc->dev, "%s: vf %d macaddr %pM\n",
			__func__, vf, vfc.macaddr);

		ret = pdsc_set_vf_config(pdsc, vf, &vfc);
		if (!ret)
			ether_addr_copy(pdsc->vfs[vf].macaddr, mac);
	}

	up_write(&pdsc->vf_op_lock);
	return ret;
}

static int pdsc_set_vf_vlan(struct net_device *netdev, int vf, u16 vlan,
			    u8 qos, __be16 proto)
{
	struct pds_core_vf_setattr_cmd vfc = { .attr = PDS_CORE_VF_ATTR_VLAN };
	struct pdsc *pdsc = *(struct pdsc **)netdev_priv(netdev);
	int ret;

	/* until someday when we support qos */
	if (qos)
		return -EINVAL;

	if (vlan > 4095)
		return -EINVAL;

	if (!netif_device_present(netdev))
		return -EBUSY;

	down_write(&pdsc->vf_op_lock);

	if (vf >= pci_num_vf(pdsc->pdev) || !pdsc->vfs) {
		ret = -EINVAL;
	} else {
		vfc.vlanid = cpu_to_le16(vlan);
		dev_dbg(pdsc->dev, "%s: vf %d vlan %d\n",
			__func__, vf, le16_to_cpu(vfc.vlanid));

		ret = pdsc_set_vf_config(pdsc, vf, &vfc);
		if (!ret)
			pdsc->vfs[vf].vlanid = cpu_to_le16(vlan);
	}

	up_write(&pdsc->vf_op_lock);
	return ret;
}

static int pdsc_set_vf_trust(struct net_device *netdev, int vf, bool set)
{
	struct pds_core_vf_setattr_cmd vfc = { .attr = PDS_CORE_VF_ATTR_TRUST };
	struct pdsc *pdsc = *(struct pdsc **)netdev_priv(netdev);
	u8 data = set;  /* convert to u8 for config */
	int ret;

	if (!netif_device_present(netdev))
		return -EBUSY;

	down_write(&pdsc->vf_op_lock);

	if (vf >= pci_num_vf(pdsc->pdev) || !pdsc->vfs) {
		ret = -EINVAL;
	} else {
		vfc.trust = set;
		dev_dbg(pdsc->dev, "%s: vf %d trust %d\n",
			__func__, vf, vfc.trust);

		ret = pdsc_set_vf_config(pdsc, vf, &vfc);
		if (!ret)
			pdsc->vfs[vf].trusted = data;
	}

	up_write(&pdsc->vf_op_lock);
	return ret;
}

static int pdsc_set_vf_rate(struct net_device *netdev, int vf,
			     int tx_min, int tx_max)
{
	struct pds_core_vf_setattr_cmd vfc = { .attr = PDS_CORE_VF_ATTR_RATE };
	struct pdsc *pdsc = *(struct pdsc **)netdev_priv(netdev);
	int ret;

	/* setting the min just seems silly */
	if (tx_min)
		return -EINVAL;

	if (!netif_device_present(netdev))
		return -EBUSY;

	down_write(&pdsc->vf_op_lock);

	if (vf >= pci_num_vf(pdsc->pdev) || !pdsc->vfs) {
		ret = -EINVAL;
	} else {
		vfc.maxrate = cpu_to_le32(tx_max);
		dev_dbg(pdsc->dev, "%s: vf %d maxrate %d\n",
			__func__, vf, le32_to_cpu(vfc.maxrate));

		ret = pdsc_set_vf_config(pdsc, vf, &vfc);
		if (!ret)
			pdsc->vfs[vf].maxrate = cpu_to_le32(tx_max);
	}

	up_write(&pdsc->vf_op_lock);
	return ret;
}

static int pdsc_set_vf_spoofchk(struct net_device *netdev, int vf, bool set)
{
	struct pds_core_vf_setattr_cmd vfc = { .attr = PDS_CORE_VF_ATTR_SPOOFCHK };
	struct pdsc *pdsc = *(struct pdsc **)netdev_priv(netdev);
	u8 data = set;  /* convert to u8 for config */
	int ret;

	if (!netif_device_present(netdev))
		return -EBUSY;

	down_write(&pdsc->vf_op_lock);

	if (vf >= pci_num_vf(pdsc->pdev) || !pdsc->vfs) {
		ret = -EINVAL;
	} else {
		vfc.spoofchk = set;
		dev_dbg(pdsc->dev, "%s: vf %d spoof %d\n",
			__func__, vf, vfc.spoofchk);

		ret = pdsc_set_vf_config(pdsc, vf, &vfc);
		if (!ret)
			pdsc->vfs[vf].spoofchk = data;
	}

	up_write(&pdsc->vf_op_lock);
	return ret;
}

static int pdsc_set_vf_link_state(struct net_device *netdev, int vf, int set)
{
	struct pds_core_vf_setattr_cmd vfc = { .attr = PDS_CORE_VF_ATTR_LINKSTATE };
	struct pdsc *pdsc = *(struct pdsc **)netdev_priv(netdev);
	u8 data;
	int ret;

	switch (set) {
	case IFLA_VF_LINK_STATE_ENABLE:
		data = PDS_CORE_VF_LINK_STATUS_UP;
		break;
	case IFLA_VF_LINK_STATE_DISABLE:
		data = PDS_CORE_VF_LINK_STATUS_DOWN;
		break;
	case IFLA_VF_LINK_STATE_AUTO:
		data = PDS_CORE_VF_LINK_STATUS_AUTO;
		break;
	default:
		return -EINVAL;
	}

	if (!netif_device_present(netdev))
		return -EBUSY;

	down_write(&pdsc->vf_op_lock);

	if (vf >= pci_num_vf(pdsc->pdev) || !pdsc->vfs) {
		ret = -EINVAL;
	} else {
		vfc.linkstate = data;
		dev_dbg(pdsc->dev, "%s: vf %d linkstate %d\n",
			__func__, vf, vfc.linkstate);

		ret = pdsc_set_vf_config(pdsc, vf, &vfc);
		if (!ret)
			pdsc->vfs[vf].linkstate = set;
	}

	up_write(&pdsc->vf_op_lock);
	return ret;
}

static const struct net_device_ops pdsc_netdev_ops = {
	.ndo_set_vf_vlan	= pdsc_set_vf_vlan,
	.ndo_set_vf_mac		= pdsc_set_vf_mac,
	.ndo_set_vf_trust	= pdsc_set_vf_trust,
	.ndo_set_vf_rate	= pdsc_set_vf_rate,
	.ndo_set_vf_spoofchk	= pdsc_set_vf_spoofchk,
	.ndo_set_vf_link_state	= pdsc_set_vf_link_state,

	.ndo_get_vf_config	= pdsc_get_vf_config,
	.ndo_get_vf_stats       = pdsc_get_vf_stats,
};

int pdsc_init_netdev(struct pdsc *pdsc)
{
	struct pdsc **p;

	// TODO: replace ether_setup with something neutered for representer
	pdsc->netdev = alloc_netdev(sizeof(struct pdsc *), "pdsc%d",
				    NET_NAME_UNKNOWN, ether_setup);
	SET_NETDEV_DEV(pdsc->netdev, pdsc->dev);
	pdsc->netdev->netdev_ops = &pdsc_netdev_ops;

	p = netdev_priv(pdsc->netdev);
	*p = pdsc;

	netif_carrier_off(pdsc->netdev);

	return register_netdev(pdsc->netdev);
}

void pdsc_vf_attr_replay(struct pdsc *pdsc)
{
	struct pds_core_vf_setattr_cmd vfc;
	struct pdsc_vf *v;
	int i;

	if (!pdsc->vfs)
		return;

	down_read(&pdsc->vf_op_lock);

	for (i = 0; i < pdsc->num_vfs; i++) {
		v = &pdsc->vfs[i];

		if (v->stats_pa) {
			vfc.attr = PDS_CORE_VF_ATTR_STATSADDR;
			vfc.stats.len = cpu_to_le32(sizeof(v->stats));
			vfc.stats.pa = cpu_to_le64(v->stats_pa);
			pdsc_set_vf_config(pdsc, i, &vfc);
			vfc.stats.pa = 0;
			vfc.stats.len = 0;
		}

		if (!is_zero_ether_addr(v->macaddr)) {
			vfc.attr = PDS_CORE_VF_ATTR_MAC;
			ether_addr_copy(vfc.macaddr, v->macaddr);
			pdsc_set_vf_config(pdsc, i, &vfc);
			eth_zero_addr(vfc.macaddr);
		}

		if (v->vlanid) {
			vfc.attr = PDS_CORE_VF_ATTR_VLAN;
			vfc.vlanid = v->vlanid;
			pdsc_set_vf_config(pdsc, i, &vfc);
			vfc.vlanid = 0;
		}

		if (v->maxrate) {
			vfc.attr = PDS_CORE_VF_ATTR_RATE;
			vfc.maxrate = v->maxrate;
			pdsc_set_vf_config(pdsc, i, &vfc);
			vfc.maxrate = 0;
		}

		if (v->spoofchk) {
			vfc.attr = PDS_CORE_VF_ATTR_SPOOFCHK;
			vfc.spoofchk = v->spoofchk;
			pdsc_set_vf_config(pdsc, i, &vfc);
			vfc.spoofchk = 0;
		}

		if (v->trusted) {
			vfc.attr = PDS_CORE_VF_ATTR_TRUST;
			vfc.trust = v->trusted;
			pdsc_set_vf_config(pdsc, i, &vfc);
			vfc.trust = 0;
		}

		if (v->linkstate) {
			vfc.attr = PDS_CORE_VF_ATTR_LINKSTATE;
			vfc.linkstate = v->linkstate;
			pdsc_set_vf_config(pdsc, i, &vfc);
			vfc.linkstate = 0;
		}
	}

	up_read(&pdsc->vf_op_lock);

	pds_devcmd_vf_start(pdsc);
}
