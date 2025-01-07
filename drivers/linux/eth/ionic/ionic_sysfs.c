// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2024 Advanced Micro Devices, Inc */

#include <linux/ctype.h>
#include <linux/inet.h>
#include <linux/inetdevice.h>
#include "ionic.h"
#include "ionic_if.h"
#include "ionic_lif.h"
#include "ionic_sysfs.h"

/**
 * ionic_sysfs_emit - scnprintf equivalent, aware of PAGE_SIZE buffer.
 * @buf: start of PAGE_SIZE buffer.
 * @fmt: format
 * @...: optional arguments to @format
 *
 * Returns number of characters written to @buf.
 */
static int ionic_sysfs_emit(char *buf, const char *fmt, ...)
{
	va_list args;
	int len;

	if (WARN(!buf || offset_in_page(buf),
		 "invalid sysfs_emit: buf:%p\n", buf))
		return 0;

	va_start(args, fmt);
	len = vscnprintf(buf, PAGE_SIZE, fmt, args);
	va_end(args);

	return len;
}

static ssize_t int_mnic_ip_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct net_device *netdev = to_net_dev(dev);
	struct ionic_lif *lif = netdev_priv(netdev);

	return ionic_sysfs_emit(buf, "%pI4/%u\n", &lif->int_mnic_ip,
				lif->int_mnic_subnet);
}

static int ionic_set_attr_mgmt_ip(struct ionic_lif *lif, __be32 addr, u8 subnet)
{
	struct ionic_admin_ctx ctx = {
		.work = COMPLETION_INITIALIZER_ONSTACK(ctx.work),
		.cmd.lif_setattr = {
			.opcode = IONIC_CMD_LIF_SETATTR,
			.index = cpu_to_le16(lif->index),
			.attr = IONIC_LIF_ATTR_MGMT_IPV4,
			.mgmt_ipv4.addr = addr,
			.mgmt_ipv4.subnet = subnet,
		},
	};

	/* don't alarm users when setting int-mnic address is unsupported by the firmware */
	return ionic_adminq_post_wait(lif, &ctx);
}

static int ionic_set_mgmt_ip(struct ionic_lif *lif, __be32 addr, u8 subnet)
{
	int err;

	if (!lif->ionic->is_mgmt_nic)
		return -EOPNOTSUPP;

	err = ionic_set_attr_mgmt_ip(lif, addr, subnet);
	if (err)
		return err;

	lif->int_mnic_ip = addr;
	lif->int_mnic_subnet = subnet;

	return 0;
}

static ssize_t int_mnic_ip_store(struct device *dev,
				 struct device_attribute *attr, const char *buf,
				 size_t count)
{
	struct net_device *netdev = to_net_dev(dev);
	const char *end;
	__be32 addr;
	u8 subnet;
	int err;

	if (!in4_pton(buf, -1, (void *)&addr, -1, &end)) {
		netdev_err(netdev, "Invalid address: %s", buf);
		return -EINVAL;
	}

	/* point to start of subnet */
	if (*end++ != '/') {
		netdev_err(netdev, "Invalid format, expected format: 1.2.3.4/24\n");
		return -EINVAL;
	}

	if (!isdigit(*end)) {
		netdev_err(netdev, "Invalid subnet");
		return -EINVAL;
	}

	err = kstrtou8(end, 10, &subnet);
	if (subnet >= 32 || !subnet) {
		netdev_err(netdev, "Invalid out of range subnet %u\n", subnet);
		return -ERANGE;
	}

	err = ionic_set_mgmt_ip(netdev_priv(netdev), addr, subnet);
	if (err) {
		netdev_err(netdev, "Failed to set int-mnic address: %pI4 subnet: %u, err: %d\n",
			   &addr, subnet, err);
		return err;
	}

	netdev_dbg(netdev, "Successfully set int-mnic address: %pI4 subnet: %u\n",
		   &addr, subnet);

	return count;
}

DEVICE_ATTR_RW(int_mnic_ip);

static struct attribute *dev_attrs[] = {
	&dev_attr_int_mnic_ip.attr,
	NULL,
};

ATTRIBUTE_GROUPS(dev);

void ionic_lif_set_mgmt_nic_sysfs_group(struct ionic_lif *lif)
{
	if (lif->ionic->is_mgmt_nic)
		lif->netdev->sysfs_groups[0] = dev_groups[0];
}
