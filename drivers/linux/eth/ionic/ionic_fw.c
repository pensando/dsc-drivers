// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2017 - 2020 Pensando Systems, Inc */

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/errno.h>

#include "ionic.h"
#include "ionic_dev.h"
#include "ionic_lif.h"

static void
ionic_dev_cmd_firmware_download(struct ionic_dev *idev, uint64_t addr,
				uint32_t offset, uint32_t length)
{
	union ionic_dev_cmd cmd = {
		.fw_download.opcode = IONIC_CMD_FW_DOWNLOAD,
		.fw_download.offset = offset,
		.fw_download.addr = addr,
		.fw_download.length = length
	};

	ionic_dev_cmd_go(idev, &cmd);
}

static void
ionic_dev_cmd_firmware_install(struct ionic_dev *idev)
{
	union ionic_dev_cmd cmd = {
		.fw_control.opcode = IONIC_CMD_FW_CONTROL,
		.fw_control.oper = IONIC_FW_INSTALL_ASYNC
	};

	ionic_dev_cmd_go(idev, &cmd);
}

static void
ionic_dev_cmd_firmware_status(struct ionic_dev *idev)
{
	union ionic_dev_cmd cmd = {
		.fw_control.opcode = IONIC_CMD_FW_CONTROL,
		.fw_control.oper = IONIC_FW_INSTALL_STATUS
	};

	ionic_dev_cmd_go(idev, &cmd);
}

static void
ionic_dev_cmd_firmware_activate(struct ionic_dev *idev, uint8_t slot)
{
	union ionic_dev_cmd cmd = {
		.fw_control.opcode = IONIC_CMD_FW_CONTROL,
		.fw_control.oper = IONIC_FW_ACTIVATE,
		.fw_control.slot = slot
	};

	ionic_dev_cmd_go(idev, &cmd);
}

int
ionic_firmware_update(struct ionic_lif *lif, const void *const fw_data, u32 fw_sz)
{
	struct ionic_dev *idev = &lif->ionic->idev;
	struct net_device *netdev = lif->netdev;
	struct ionic *ionic = lif->ionic;
	union ionic_dev_cmd_comp comp;
	u32 buf_sz, copy_sz, offset;
	int err = 0;
	u8 fw_slot;

	buf_sz = sizeof(idev->dev_cmd_regs->data);

	netdev_info(netdev,
		"downloading firmware - size %d part_sz %d nparts %d\n",
		fw_sz, buf_sz, DIV_ROUND_UP(fw_sz, buf_sz));

	offset = 0;
	while (offset < fw_sz) {
		copy_sz = min(buf_sz, fw_sz - offset);
		mutex_lock(&ionic->dev_cmd_lock);
		memcpy_toio(&idev->dev_cmd_regs->data, fw_data + offset, copy_sz);
		ionic_dev_cmd_firmware_download(idev,
			offsetof(union ionic_dev_cmd_regs, data), offset, copy_sz);
		err = ionic_dev_cmd_wait(ionic, devcmd_timeout);
		mutex_unlock(&ionic->dev_cmd_lock);
		if (err) {
			netdev_err(netdev,
				"download failed offset 0x%x addr 0x%lx len 0x%x\n",
				offset, offsetof(union ionic_dev_cmd_regs, data), copy_sz);
			goto err_out;
		}
		offset += copy_sz;
	}

	netdev_info(netdev, "installing firmware\n");

	mutex_lock(&ionic->dev_cmd_lock);
	ionic_dev_cmd_firmware_install(idev);
	err = ionic_dev_cmd_wait(ionic, devcmd_timeout);
	ionic_dev_cmd_comp(idev, (union ionic_dev_cmd_comp *)&comp);
	fw_slot = comp.fw_control.slot;
	mutex_unlock(&ionic->dev_cmd_lock);
	if (err) {
		netdev_err(netdev, "failed to start firmware install\n");
		goto err_out;
	}

	mutex_lock(&ionic->dev_cmd_lock);
	ionic_dev_cmd_firmware_status(idev);
	err = ionic_dev_cmd_wait(ionic, IONIC_FW_INSTALL_TIMEOUT);
	mutex_unlock(&ionic->dev_cmd_lock);
	if (err) {
		netdev_err(netdev, "firmware install failed\n");
		goto err_out;
	}

	netdev_info(netdev, "activating firmware - slot %d\n", fw_slot);

	mutex_lock(&ionic->dev_cmd_lock);
	ionic_dev_cmd_firmware_activate(idev, fw_slot);
	err = ionic_dev_cmd_wait(ionic, IONIC_FW_ACTIVATE_TIMEOUT);
	mutex_unlock(&ionic->dev_cmd_lock);
	if (err) {
		netdev_err(netdev, "firmware activation failed\n");
		goto err_out;
	}

err_out:
	return err;
}
